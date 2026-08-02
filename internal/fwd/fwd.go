// Package fwd implements the accept-loop core of the "fwd" verb: an ad-hoc
// local TCP listener that forwards every accepted connection to a named
// route-table target through the daemon's IPC socket, one fresh attach per
// accepted connection. See cmd/quic-link/fwd.go for the thin cobra wrapper
// that parses arguments, binds the local port, and prints the CONTRACT line
// — the shape daemoncmd.go already uses to wrap internal/daemon.
//
// This package is deliberately separate from cmd/quic-link, which has no
// goroutine-leak guard anywhere in it today: fwd's accept loop, with its
// per-connection goroutines and shutdown registry, is the most
// goroutine-lifecycle-sensitive code added in this step, and it is born
// under a leak guard (see fwd_test.go's TestMain) from its very first
// commit rather than bolted on later.
package fwd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// Attacher opens one forward to server/target and returns the live
// connection ready to splice, or an error. *ipc.Client satisfies this
// interface as-is, with no wrapper needed, which is what lets tests script
// exact scenarios (success, a daemon-scoped failure, an agent-scoped
// refusal, a hang) without a real daemon or a real agent standing behind
// this Forwarder.
type Attacher interface {
	Attach(server, target string, meta map[string]string) (net.Conn, error)
}

// defaultMaxConcurrent is fwd's own local cap on simultaneous forwards. It is
// deliberately separate from the daemon's global in-flight-attach cap
// (internal/ipc's own defaultAttachCap): if fwd itself is the thing running
// out of capacity, the failure should be local and legible (a clear refusal
// from fwd) rather than surfacing as a mysterious daemon-wide attach failure
// in some unrelated verb sharing the same socket. Not a contractual value.
const defaultMaxConcurrent = 64

// Options configures optional tuning of a Forwarder. The zero value uses the
// package defaults.
type Options struct {
	// MaxConcurrent bounds the number of simultaneous forwards this
	// Forwarder will hold open before refusing new local connections.
	// Zero means defaultMaxConcurrent.
	MaxConcurrent int
}

// Forwarder runs the accept loop for one ad-hoc fwd instance: one already-
// bound local listener, one (server, target) pair, and a bounded set of
// concurrently spliced connections.
type Forwarder struct {
	server string
	target string
	ln     net.Listener
	att    Attacher

	sem chan struct{}
	reg *registry
	wg  sync.WaitGroup
}

// New constructs a Forwarder. ln must already be bound (bind-and-hold:
// callers must never probe-close-rebind); Run takes ownership of it and
// closes it during shutdown.
func New(server, target string, ln net.Listener, att Attacher, opts Options) *Forwarder {
	max := opts.MaxConcurrent
	if max <= 0 {
		max = defaultMaxConcurrent
	}
	return &Forwarder{
		server: server,
		target: target,
		ln:     ln,
		att:    att,
		sem:    make(chan struct{}, max),
		reg:    newRegistry(),
	}
}

// RegistrySize reports the number of forwards currently in flight (accepted
// but not yet fully torn down). Exported so tests can assert shutdown
// completeness directly by observing the count reach zero, rather than
// inferring completion from elapsed time.
func (f *Forwarder) RegistrySize() int {
	return f.reg.size()
}

// Run accepts local connections until ctx is cancelled, then resets every
// in-flight forward and waits for every goroutine this Forwarder started to
// exit before returning. Callers can rely on this: once Run returns, the
// local listener is closed, no more forwards are being accepted, and
// RegistrySize is zero.
func (f *Forwarder) Run(ctx context.Context) {
	f.wg.Add(1)
	go f.acceptLoop(ctx)
	f.wg.Wait()
}

// acceptLoop accepts local TCP connections and hands each to handleConn in
// its own goroutine, so one slow attach never blocks the next accept. It
// stops when ctx is cancelled (which closes the listener, unblocking
// Accept) or when the listener errors for any other reason.
func (f *Forwarder) acceptLoop(ctx context.Context) {
	defer f.wg.Done()

	// Watch ctx: on shutdown, reset every in-flight forward first, then close
	// the listener so Accept unblocks. Resetting before closing (rather than
	// after) is not what closes the accept-vs-shutdown race — the mutex
	// inside registry does that regardless of this ordering — but it does
	// mean a connection that is already registered by the time this fires
	// gets torn down as early as possible.
	done := make(chan struct{})
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		select {
		case <-ctx.Done():
			f.reg.closeAll()
			_ = f.ln.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		conn, err := f.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				// The watcher goroutine already closed (or is closing) the
				// listener in response to ctx cancellation: the clean
				// shutdown signal. Nothing further to close or log here.
				return
			}
			// A genuine fault (the realistic case is local fd exhaustion),
			// not something this Forwarder caused. Run's own promise is
			// that the listener is closed once Run returns, unconditionally
			// — so close it here and log at error level, rather than
			// silently returning and leaving the process looking like it is
			// still listening when it has actually stopped accepting.
			slog.Error("fwd: accept failed; closing listener and stopping the forward",
				"server", f.server, "target", f.target, "err", err)
			_ = f.ln.Close()
			return
		}
		select {
		case f.sem <- struct{}{}:
		default:
			slog.Warn("fwd: local concurrency cap reached; refusing connection",
				"server", f.server, "target", f.target)
			tunnel.ResetConn(conn)
			continue
		}
		f.wg.Add(1)
		go f.handleConn(conn)
	}
}

// handleConn drives one accepted local connection through registration,
// Attach, and the splice. It deregisters itself via defer on every exit path
// so RegistrySize always converges to zero once every goroutine has exited,
// and it always releases its concurrency-cap slot via defer for the same
// reason. Attach is not context-bound (it matches ipc.Client.Attach's own
// signature, which carries its own internal timeouts), so handleConn does
// not take one either.
func (f *Forwarder) handleConn(local net.Conn) {
	defer f.wg.Done()
	defer func() { <-f.sem }()

	id, ok := f.reg.register(local)
	if !ok {
		// Shutdown has already begun: this connection was accepted too late
		// to be caught by the shutdown sweep, so reset it here directly
		// instead of ever calling Attach. This is the other half of the
		// accept-vs-shutdown race fix — see registry.register's doc comment.
		tunnel.ResetConn(local)
		return
	}
	defer f.reg.deregister(id)

	remote, err := f.att.Attach(f.server, f.target, map[string]string{"reqid": tunnel.NewReqID()})
	if err != nil {
		// Once listening, no single connection's failure is fatal to fwd —
		// this is the deliberate opposite of the startup preflight's
		// status-3 handling, which exits rather than warns, because there is
		// no listener yet worth keeping open before the very first
		// successful validation. Here there already is one, and a
		// long-running forward should survive a daemon restart or a
		// mid-flight route table change on the remote end.
		logAttachFailure(f.server, f.target, err)
		tunnel.ResetConn(local)
		return
	}

	if !f.reg.setRemote(id, remote) {
		// closeAll ran between register and here: the local leg was already
		// reset by the sweep. Clean up the remote leg ourselves and stop —
		// never call Pipe on a connection the sweep has already torn down
		// half of.
		tunnel.ResetConn(remote)
		tunnel.ResetConn(local)
		return
	}

	tunnel.Pipe(local, remote)
}

// logAttachFailure logs a single accepted connection's attach failure at
// warn level. The message prefix distinguishes a daemon-scoped failure
// (this machine's session is not ready, transient, no agent was ever
// reached) from an agent-scoped one (the remote route table authoritatively
// refused), the same split already load-bearing in the daemon's own IPC
// server (internal/ipc/server.go). Blaming "the agent" for a daemon-scoped
// failure would send an operator to debug the wrong host — the same defect
// shape a previous field campaign already found and fixed once in a
// different verb.
func logAttachFailure(server, target string, err error) {
	var ae *ipc.AttachStatusError
	if errors.As(err, &ae) && isAgentScoped(ae.Status) {
		slog.Warn("fwd: agent refused connection; forward continues listening",
			"server", server, "target", target, "status", ae.Status, "msg", ae.Msg)
		return
	}
	slog.Warn("fwd: attach failed for one connection; forward continues listening",
		"server", server, "target", target, "err", err)
}

// isAgentScoped reports whether status is an authoritative, permanent
// refusal from the remote agent's route table (unauthorized, or an unknown
// target / dial failure / draining agent, both mapped to exit code 5) as
// opposed to a daemon-scoped, transient condition (this machine's session is
// not ready, the server is unknown or disabled from this daemon's own point
// of view, or the daemon's own in-flight-attach cap was reached — all of
// which currently share status 3 or fall through to the generic status 1).
//
// This split is not invented here: it is already load-bearing in
// internal/ipc/server.go, which returns status 3 at both its unknown/
// disabled-server fast-fail check and its pool-not-ready timeout, while a
// genuine non-OK response relayed from the agent goes through the already-
// mapped exit-code path. Both the startup preflight and the accept loop's
// per-connection failure handling call this so the same finding is never
// classified two different ways inside one verb.
//
// This mapping is not exhaustive of every possible status value: status 1
// is treated as daemon-scoped here, which is correct for the daemon's own
// fast-fail conditions, but would also be wrong for a genuinely agent-scoped
// response the exit-code mapping does not yet have a dedicated case for
// (for example a currently-unmapped protocol status such as a bad header or
// an unsupported version, which falls through to the generic default
// rather than to 4 or 5). Any status value added to the protocol in the
// future needs the same "is this an authoritative answer from the agent"
// judgement applied explicitly here, rather than assumed from its numeric
// value. Treating an unmapped value as daemon-scoped (warn and keep
// listening) rather than agent-scoped (fail and stop) is the deliberately
// conservative default direction: a false warning that the accept loop's
// own attaches can still recover from is a smaller mistake than a forward
// that stops listening over a status this function does not yet recognize.
func isAgentScoped(status int) bool {
	return status == 4 || status == 5
}
