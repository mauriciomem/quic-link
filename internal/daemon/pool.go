package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/backoff"
	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ExponentialReconnectPolicy is the production reconnect policy. It is an
// alias: the schedule itself lives in the shared backoff package because the
// agent owns reconnection in reverse mode and cannot import this package.
type ExponentialReconnectPolicy = backoff.Exponential

// DefaultReconnectPolicy returns the project-standard reconnect schedule.
func DefaultReconnectPolicy() ReconnectPolicy {
	return backoff.Default()
}

// WallClock is the production Clock implementation using real wall-clock time.
type WallClock struct{}

// Now returns the current wall-clock time.
func (WallClock) Now() time.Time { return time.Now() }

// Since returns the duration elapsed since t.
func (WallClock) Since(t time.Time) time.Duration { return time.Since(t) }

// After returns a channel that fires after d.
func (WallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// ---- Liveness probe constants and policy -----------------------------------

// Default liveness probe parameters. These are deliberately separate from the
// QUIC idle-timeout (60s) and keep-alive (15s) settings — the probe is an
// application-level detector that fires substantially faster.
const (
	// DefaultProbeInterval is how often the liveness probe sends a Ping while
	// a session is connected. Two consecutive failures at this interval detect
	// a dead agent in approximately 2×interval + 2×ProbeTimeout.
	DefaultProbeInterval = 10 * time.Second

	// DefaultProbeTimeout is the per-probe deadline. If the agent does not
	// reply within this window the probe counts as a failure.
	DefaultProbeTimeout = 5 * time.Second

	// DefaultProbeFailThreshold is the number of consecutive probe failures
	// before the session is declared lost. Two failures keeps the detection
	// window to roughly 25 s (interval + timeout + interval + timeout) while
	// avoiding false positives from a single momentary hiccup.
	DefaultProbeFailThreshold = 2

	// transportRebindAfter is the number of consecutive dial failures after
	// which the entry closes its current UDP transport and builds a new one.
	// A rebind fires at every multiple of this value (10, 20, 30, …); the
	// counter only resets when a dial succeeds, so rebinds repeat until
	// recovery. The wall-clock spacing between rebinds depends on the
	// reconnect backoff policy: at the production cap (15 s per attempt) a
	// single rebind cycle spans roughly 2.5 minutes, which is far below an
	// 84-minute NAT-poisoning outage and far above a routine agent restart.
	// In tests with zero-delay backoff the same N failures happen in
	// microseconds.
	transportRebindAfter = 10
)

// LivenessPolicy controls the application-level keepalive probe that the daemon
// runs on each connected session. Inject a fast fake in tests to avoid sleeping
// for the real 10s/5s intervals.
type LivenessPolicy interface {
	// Interval returns the time between successive probes while connected.
	Interval() time.Duration
	// Timeout returns the per-probe deadline. A probe that takes longer than
	// this counts as a failure.
	Timeout() time.Duration
	// FailThreshold returns how many consecutive failures declare the session
	// lost and trigger a reconnect.
	FailThreshold() int
}

// DefaultLivenessPolicy returns the production liveness policy.
type DefaultLivenessPolicy struct{}

func (DefaultLivenessPolicy) Interval() time.Duration { return DefaultProbeInterval }
func (DefaultLivenessPolicy) Timeout() time.Duration  { return DefaultProbeTimeout }
func (DefaultLivenessPolicy) FailThreshold() int      { return DefaultProbeFailThreshold }

// ---- realPool ---------------------------------------------------------------

// realPool is the production SessionPool. It holds one SessionEntry per
// configured server.
type realPool struct {
	entries map[string]SessionEntry
	order   []string // stable iteration order for State()
}

// NewRealPool constructs a pool from the config. One dialEntry is created per
// enabled server; disabled servers get a disabledEntry stub. Dialing begins
// immediately (eager) for each enabled server.
//
// makeTransport is a factory called once per enabled server at pool
// construction to obtain the initial transport. It is also stored in the
// dialEntry and called again when the entry determines a UDP socket rebind is
// needed (after transportRebindAfter consecutive dial failures). Each call to
// makeTransport must bind a fresh UDP socket for the named server.
//
// boundPorts carries the actual local TCP ports that have been successfully
// bound for each server (ssh and docker). For an enabled server present in
// boundPorts the pool reports those ports in status; for a server absent from
// the map (acquisition failed) or for disabled servers the pool reports 0/0.
// This makes the reported addresses reflect what is actually bound, not the
// configured ideal.
func NewRealPool(
	ctx context.Context,
	cfg *config.Config,
	makeTransport func(serverName string, srv config.Server) (transport.Transport, error),
	policy ReconnectPolicy,
	clock Clock,
	boundPorts map[string][2]int,
) (*realPool, error) {
	return NewRealPoolWithLiveness(ctx, cfg, makeTransport, policy, clock, boundPorts, DefaultLivenessPolicy{})
}

// NewRealPoolWithLiveness is the constructor that also accepts a LivenessPolicy.
// Tests call this directly to inject fast probe intervals without waiting for
// the production 10s/5s parameters.
func NewRealPoolWithLiveness(
	ctx context.Context,
	cfg *config.Config,
	makeTransport func(serverName string, srv config.Server) (transport.Transport, error),
	policy ReconnectPolicy,
	clock Clock,
	boundPorts map[string][2]int,
	liveness LivenessPolicy,
) (*realPool, error) {
	p := &realPool{
		entries: make(map[string]SessionEntry),
	}

	names := sortedServerNames(cfg.Servers)
	for _, name := range names {
		srv := cfg.Servers[name]

		if srv.Enabled != nil && !*srv.Enabled {
			// Disabled servers: report 0/0 — nothing is listening.
			p.entries[name] = &disabledEntry{
				name:      name,
				since:     clock.Now(),
				transport: configuredTransport(srv),
			}
			p.order = append(p.order, name)
			continue
		}

		// Use the actually-bound ports when available. If port acquisition
		// failed for this server (absent from boundPorts), report 0/0 so
		// status never names a port that has no listener.
		sshPort, dockerPort := 0, 0
		if ports, ok := boundPorts[name]; ok {
			sshPort, dockerPort = ports[0], ports[1]
		}

		t, err := makeTransport(name, srv)
		if err != nil {
			return nil, fmt.Errorf("pool: build transport for %q: %w", name, err)
		}

		// Which kind of entry a server gets follows the same predicate that
		// decides what direction it reports, so the two can never disagree.
		// Falling through to a dialing entry for a server configured to wait
		// would build one with no address and retry nothing forever.
		if configuredTransport(srv) == transportListen {
			ln, lerr := t.Listen()
			if lerr != nil {
				_ = t.Close()
				return nil, fmt.Errorf("pool: listen for %q: %w", name, lerr)
			}
			p.entries[name] = newListenEntry(ctx, name, ln, t, sshPort, dockerPort, clock, liveness)
			p.order = append(p.order, name)
			continue
		}

		// Capture name and srv for the closure — do not use the loop variable
		// directly (Go loop-variable capture: each iteration creates fresh
		// bindings in Go ≥1.22, but we make the capture explicit for clarity).
		entryName := name
		entrySrv := srv
		factory := func() (transport.Transport, error) {
			return makeTransport(entryName, entrySrv)
		}

		entry := newDialEntry(ctx, name, srv.Addr, t, factory, sshPort, dockerPort, policy, clock, liveness)
		p.entries[name] = entry
		p.order = append(p.order, name)
	}

	return p, nil
}

// Get returns the live transport connection for the named server.
func (p *realPool) Get(ctx context.Context, server string) (Conn, error) {
	entry, ok := p.entries[server]
	if !ok {
		return nil, fmt.Errorf("pool: unknown server %q", server)
	}
	return entry.Get(ctx)
}

// State returns a snapshot of all server connection states, in stable order.
func (p *realPool) State() []SessionState {
	states := make([]SessionState, 0, len(p.order))
	for _, name := range p.order {
		states = append(states, p.entries[name].State())
	}
	return states
}

// EntryState returns the connection-state string for a single server.
func (p *realPool) EntryState(server string) (string, error) {
	entry, ok := p.entries[server]
	if !ok {
		return "", fmt.Errorf("unknown server %q", server)
	}
	return entry.State().State, nil
}

// Close tears down all pool entries.
func (p *realPool) Close() {
	for _, entry := range p.entries {
		entry.Close(fmt.Errorf("daemon shutting down"))
	}
}

// sortedServerNames returns config server names in ascending order.
func sortedServerNames(servers map[string]config.Server) []string {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// ---- disabledEntry ----------------------------------------------------------

// configuredTransport reports which side opens the connection for a server, as
// its configuration asks for it: a listen address with no dial address means
// the peer connects to us. Everything else is the ordinary case where we dial
// out, which is also the safe answer for a half-written config, since it is
// what the daemon would actually attempt.
// The two directions a server can be configured for, as reported by status and
// as used to decide which kind of entry the pool builds for it.
const (
	transportDial   = "dial"
	transportListen = "listen"
)

func configuredTransport(srv config.Server) string {
	if srv.Listen != "" && srv.Addr == "" {
		return transportListen
	}
	return transportDial
}

type disabledEntry struct {
	name  string
	since time.Time
	// transport is the direction this server's config asks for, kept so a
	// disabled entry still reports the truth about itself rather than
	// assuming the forward-mode default.
	transport string
}

func (e *disabledEntry) Get(_ context.Context) (Conn, error) {
	return nil, fmt.Errorf("server %q is disabled", e.name)
}

func (e *disabledEntry) State() SessionState {
	return SessionState{
		Name:      e.name,
		State:     "disabled",
		Transport: e.transport,
		Since:     e.since,
		// SSHPort and DockerPort are 0: no listener is bound for a disabled
		// server. A status field that reports phantom ports is worse than
		// one that is absent.
	}
}

func (e *disabledEntry) Close(_ error) {}

// ---- dialEntry --------------------------------------------------------------

// internalConnState tracks the richer internal lifecycle.
//
//   - stateConnecting: initial dial underway.
//   - stateConnected: a live connection is held.
//   - stateReconnecting: connection dropped; re-dialing.
//   - stateAuthFailed: permanent authentication rejection; the loop has exited
//     and will never retry. This projects to "auth_failed" in the external enum
//     so consumers can distinguish a permanent identity mismatch from a transient
//     "connecting" condition.
type internalConnState int

const (
	stateConnecting internalConnState = iota
	stateConnected
	stateReconnecting
	stateAuthFailed
)

// dialEntry is the production SessionEntry for a forward-mode (dial-out)
// server. It establishes the connection eagerly at construction, opens the
// control stream, and re-dials continuously after every drop.
//
// Per-entry isolation is a hard invariant: no lock or goroutine is shared with
// other pool entries. One entry stuck in backoff cannot block another entry's
// State() snapshot or Get() call.
type dialEntry struct {
	name string
	addr string
	// t is the active transport. It is written only by runLoop (closed and
	// replaced on rebind, or initially set from newDialEntry). No other
	// goroutine reads or writes t, so no lock is needed for it. The probe
	// goroutine does not touch t — it uses the controlClient captured at
	// dial time. Verified: Get/State/Close read only e.current and e.intState
	// under e.mu, not e.t.
	t transport.Transport
	// factory creates a fresh transport (new UDP socket) when called. Used to
	// rebind the source port after transportRebindAfter consecutive dial
	// failures, which recovers from NAT/CGNAT 4-tuple poisoning where no
	// retry on the old socket can ever succeed.
	factory    func() (transport.Transport, error)
	policy     ReconnectPolicy
	clock      Clock
	liveness   LivenessPolicy
	sshPort    int
	dockerPort int

	mu            sync.Mutex
	intState      internalConnState
	current       transport.Conn
	controlClient *control.Client
	// dialDone is closed when the in-flight dial finishes. It is non-nil only
	// while a dial is underway (dialing == true).
	dialDone chan struct{}
	dialing  bool
	dialErr  error
	since    time.Time

	cancel context.CancelFunc
	// runDone is closed when runLoop exits, allowing Close to detect completion.
	runDone chan struct{}
}

// newDialEntry creates a dialEntry and starts its run-loop immediately.
func newDialEntry(
	parentCtx context.Context,
	name, addr string,
	t transport.Transport,
	factory func() (transport.Transport, error),
	sshPort, dockerPort int,
	policy ReconnectPolicy,
	clock Clock,
	liveness LivenessPolicy,
) *dialEntry {
	ctx, cancel := context.WithCancel(parentCtx)
	e := &dialEntry{
		name:       name,
		addr:       addr,
		t:          t,
		factory:    factory,
		policy:     policy,
		clock:      clock,
		liveness:   liveness,
		sshPort:    sshPort,
		dockerPort: dockerPort,
		intState:   stateConnecting,
		since:      clock.Now(),
		dialing:    true,
		dialDone:   make(chan struct{}),
		cancel:     cancel,
		runDone:    make(chan struct{}),
	}
	go e.runLoop(ctx)
	return e
}

// runLoop is the per-entry goroutine. It dials, opens the control stream, waits
// for a drop, and repeats. It exits when ctx is cancelled.
//
// Only runLoop reads or writes e.t. Probe goroutines are spawned inside
// runLoop under the entry's context and use only the controlClient captured
// at dial time, not e.t. This means no lock is required for e.t.
func (e *dialEntry) runLoop(ctx context.Context) {
	defer close(e.runDone)

	attempt := 0
	consecutiveFails := 0
	var lastSuccessAt time.Time // zero means never connected

	for {
		if ctx.Err() != nil {
			// Wake any blocked Get callers with the ctx error.
			e.mu.Lock()
			e.dialErr = ctx.Err()
			done := e.dialDone
			e.dialing = false
			e.mu.Unlock()
			if done != nil {
				close(done)
			}
			return
		}

		// Log the local UDP 4-tuple, consecutive-failure count, and elapsed
		// time since the last successful connection on every dial attempt so
		// operators can diagnose NAT/CGNAT 4-tuple poisoning without needing
		// to reproduce the failure.
		localAddr := localAddrOf(e.t)
		elapsedSinceSuccess := time.Duration(0)
		if !lastSuccessAt.IsZero() {
			elapsedSinceSuccess = e.clock.Since(lastSuccessAt)
		}
		slog.Debug("session dialing",
			"role", "daemon",
			"session", e.name,
			"local_addr", localAddr,
			"consecutive_fails", consecutiveFails,
			"elapsed_since_success", elapsedSinceSuccess,
		)

		conn, cclient, err := e.dialAndOpen(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Auth failures are permanent — no point retrying.
			if transport.IsAuthFailed(err) {
				slog.Error("session auth failed; giving up",
					"role", "daemon", "session", e.name, "err", err)
				e.mu.Lock()
				e.intState = stateAuthFailed
				e.dialErr = err
				done := e.dialDone
				e.dialing = false
				e.mu.Unlock()
				if done != nil {
					close(done)
				}
				return
			}

			consecutiveFails++
			d := e.policy.Backoff(attempt)
			attempt++

			// Log the observable reconnect state: attempt number, next-retry
			// interval, local address, and elapsed time since the last
			// successful connection. These are log-only; the emitted JSON
			// enum still maps to "connecting" for both reconnecting and
			// initial-connecting states.
			slog.Warn("agent lost; reconnecting",
				"role", "daemon",
				"session", e.name,
				"attempt", attempt,
				"next_retry_in", d,
				"local_addr", localAddr,
				"consecutive_fails", consecutiveFails,
				"elapsed_since_success", elapsedSinceSuccess,
				"err", err,
			)

			// Record the error so Get() callers can surface it.
			e.mu.Lock()
			e.dialErr = err
			done := e.dialDone
			e.dialing = false
			e.mu.Unlock()
			if done != nil {
				close(done)
			}

			// After N consecutive dial failures, close the old transport and
			// build a new one with a fresh UDP socket. This recovers from NAT
			// or CGNAT 4-tuple poisoning where no retry on the poisoned source
			// port can ever succeed — only a new source port can establish a
			// fresh path through the NAT.
			//
			// runLoop is the sole writer of e.t (proven by the struct comment
			// above), and no dial is in flight at this point, so we do not
			// need any additional locking here.
			if consecutiveFails%transportRebindAfter == 0 {
				oldAddr := localAddrOf(e.t)
				if rbErr := e.rebindTransport(); rbErr != nil {
					slog.Error("session transport rebind failed",
						"role", "daemon",
						"session", e.name,
						"old_local_addr", oldAddr,
						"err", rbErr,
					)
				} else {
					slog.Info("session transport rebound",
						"role", "daemon",
						"session", e.name,
						"old_local_addr", oldAddr,
						"new_local_addr", localAddrOf(e.t),
						"consecutive_fails", consecutiveFails,
					)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-e.clock.After(d):
			}

			// Prepare for the next attempt.
			e.mu.Lock()
			e.dialing = true
			e.dialDone = make(chan struct{})
			e.dialErr = nil
			e.mu.Unlock()
			continue
		}

		// Whether this is the first connection ever or a reconnect after a
		// drop, track it so we can log "reconnected" on recovery.
		wasConnectedBefore := !lastSuccessAt.IsZero()

		// Successful dial — reset counters.
		consecutiveFails = 0
		lastSuccessAt = e.clock.Now()
		attempt = 0

		if wasConnectedBefore {
			slog.Info("reconnected to server", "role", "daemon", "session", e.name)
		} else {
			slog.Info("connected to server", "role", "daemon", "session", e.name)
		}

		// probeResult carries structured detail from the liveness probe when it
		// is the one that declared the session dead. It is nil when the drop
		// was a natural QUIC event (NAT timeout, agent restart, idle timeout).
		// The channel is buffered-1 so the probe goroutine never blocks on send.
		probeResult := make(chan *probeDeathDetail, 1)

		// Launch the liveness probe goroutine under this entry's context.
		// It runs concurrently with the <-conn.Context().Done() wait below.
		// When the probe detects consecutive failures it sends its detail on
		// probeResult, then closes the connection via CloseWithError, which
		// cancels conn.Context() and causes the <-conn.Context().Done() below
		// to fire — the same path as a natural drop. This avoids
		// double-triggering: whichever fires first (probe or natural drop)
		// cancels conn.Context(), and the other either observes a closed conn
		// context (and stops) or observes a connection already being torn down.
		// The probe goroutine is joined via the probeDone channel before
		// proceeding to the next loop iteration.
		probeDone := make(chan struct{})
		probeCtx, probeCancel := context.WithCancel(ctx)
		go func() {
			defer close(probeDone)
			e.runLivenessProbe(probeCtx, conn, cclient, probeResult)
		}()

		// Wait for the connection to drop (either a natural QUIC drop or the
		// liveness probe declaring it dead via CloseWithError above).
		<-conn.Context().Done()

		// Stop the probe goroutine. If the probe triggered the close it is
		// already done; if the connection dropped naturally probeCancel stops
		// the next probe from starting. Either way we join the goroutine.
		probeCancel()
		<-probeDone

		if ctx.Err() != nil {
			// Graceful shutdown — do not log a spurious "session lost".
			return
		}

		// Emit the canonical "session lost" event exactly once per actual loss,
		// regardless of which detector noticed it. Operators can find every
		// session loss by filtering on this single message. The structured
		// attribute "detector" distinguishes the liveness probe path from a
		// natural QUIC drop (NAT timeout, agent restart, idle timeout). When
		// the probe was the detector, its failure count is included as additional
		// context, but the canonical event is never suppressed.
		select {
		case detail := <-probeResult:
			// The liveness probe declared the death; include its diagnostic detail.
			slog.Warn("session lost; reconnecting",
				"role", "daemon",
				"session", e.name,
				"detector", "liveness_probe",
				"consecutive_probe_failures", detail.consecutiveFailures,
			)
		default:
			// Natural QUIC drop (NAT timeout, network change, agent restart,
			// QUIC idle timeout) — no probe detail available.
			slog.Warn("session lost; reconnecting",
				"role", "daemon",
				"session", e.name,
				"detector", "quic_drop",
			)
		}

		// Reset attempt counter if we were stable long enough.
		if e.clock.Since(lastSuccessAt) > e.policy.StableAfter() {
			attempt = 0
		}

		// Transition to reconnecting state and prepare the next dial slot.
		e.mu.Lock()
		e.intState = stateReconnecting
		e.current = nil
		e.since = e.clock.Now()
		if cclient != nil {
			_ = cclient.Close()
		}
		e.controlClient = nil
		e.dialing = true
		e.dialDone = make(chan struct{})
		e.dialErr = nil
		e.mu.Unlock()
	}
}

// probeDeathDetail carries structured context from the liveness probe when it
// is the detector that declared a session lost. Sent on the probeResult channel
// so the runLoop can emit the canonical "session lost" event with the probe's
// diagnostic detail attached.
type probeDeathDetail struct {
	consecutiveFailures int
}

// runLivenessProbe sends periodic Ping RPCs over cclient while probeCtx is
// not cancelled. If FailThreshold consecutive probes time out or fail, it
// sends its diagnostic detail on probeResult and then calls conn.CloseWithError
// so the main runLoop can re-dial. Probe failures caused by context
// cancellation (daemon shutting down) are not counted and do not trigger a
// reconnect.
//
// The probe goroutine is the sole caller of cclient.PingRTT inside a
// connected session — the control client is not used anywhere else concurrently.
func (e *dialEntry) runLivenessProbe(probeCtx context.Context, conn transport.Conn, cclient *control.Client, probeResult chan<- *probeDeathDetail) {
	runLivenessProbeOn(probeCtx, e.clock, e.liveness, e.name, conn, cclient, probeResult)
}

// runLivenessProbeOn is the probe itself, independent of which kind of entry
// owns the session. The control client sits on this side of the connection
// whichever end opened the transport, so the probe is identical in both
// directions; only what the caller does after a detected loss differs.
func runLivenessProbeOn(
	probeCtx context.Context,
	clock Clock,
	liveness LivenessPolicy,
	name string,
	conn transport.Conn,
	cclient *control.Client,
	probeResult chan<- *probeDeathDetail,
) {
	consecutiveFailures := 0
	interval := liveness.Interval()
	timeout := liveness.Timeout()
	threshold := liveness.FailThreshold()

	for {
		select {
		case <-probeCtx.Done():
			return
		case <-clock.After(interval):
		}

		if probeCtx.Err() != nil {
			return
		}

		pingCtx, pingCancel := context.WithTimeout(probeCtx, timeout)
		_, err := cclient.PingRTT(pingCtx)
		pingCancel()

		if err == nil {
			consecutiveFailures = 0
			continue
		}

		// A probe failure caused by the probe context being cancelled means
		// the daemon is shutting down or the run-loop already declared the
		// session dead. Do not count it as a liveness failure.
		if probeCtx.Err() != nil {
			return
		}

		consecutiveFailures++
		slog.Warn("liveness probe failed",
			"role", "daemon",
			"session", name,
			"consecutive_probe_failures", consecutiveFailures,
			"threshold", threshold,
			"err", err,
		)

		if consecutiveFailures >= threshold {
			// Send diagnostic detail to the runLoop so it can emit the
			// canonical "session lost" event with probe context attached.
			// The channel is buffered-1; this send never blocks. The runLoop
			// always reads after <-probeDone, so the send completes before
			// the channel is GC'd.
			select {
			case probeResult <- &probeDeathDetail{consecutiveFailures: consecutiveFailures}:
			default:
			}
			// Close the connection so conn.Context() is cancelled, waking the
			// main runLoop's <-conn.Context().Done(). The error code 0 is an
			// application-level graceful close; the agent will see a
			// CONNECTION_CLOSE and clean up its side.
			_ = conn.CloseWithError(0, "liveness probe: no response from agent")
			return
		}
	}
}

// rebindTransport closes the current transport and builds a new one via the
// factory. On success e.t points at the fresh transport. On failure e.t is
// unchanged (the caller should log and continue with the old transport).
func (e *dialEntry) rebindTransport() error {
	newT, err := e.factory()
	if err != nil {
		return fmt.Errorf("build replacement transport: %w", err)
	}
	// Close the old transport so the UDP socket is released.
	if closeErr := e.t.Close(); closeErr != nil {
		slog.Warn("close old transport during rebind",
			"role", "daemon", "session", e.name, "err", closeErr)
	}
	e.t = newT
	return nil
}

// localAddrOf returns the local UDP address of t if t implements the optional
// LocalAddrProvider interface, otherwise returns "<unavailable>".
func localAddrOf(t transport.Transport) string {
	if lap, ok := t.(transport.LocalAddrProvider); ok {
		if addr := lap.LocalAddr(); addr != nil {
			return addr.String()
		}
	}
	return "<unavailable>"
}

// dialAndOpen dials addr and opens the control stream. On success it records
// the live connection under the mutex and wakes blocked Get callers.
func (e *dialEntry) dialAndOpen(ctx context.Context) (transport.Conn, *control.Client, error) {
	conn, err := e.t.Dial(ctx, e.addr)
	if err != nil {
		return nil, nil, err
	}

	cclient, err := openControlStream(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(0x03, "control open failed")
		return nil, nil, err
	}

	// Record the live connection and wake blocked Get callers.
	e.mu.Lock()
	e.intState = stateConnected
	e.current = conn
	e.controlClient = cclient
	e.dialErr = nil
	done := e.dialDone
	e.dialing = false
	e.since = e.clock.Now()
	e.mu.Unlock()

	if done != nil {
		close(done)
	}

	return conn, cclient, nil
}

// Get returns the live transport connection, blocking if a dial is in progress.
func (e *dialEntry) Get(ctx context.Context) (Conn, error) {
	for {
		e.mu.Lock()
		if e.current != nil {
			c := e.current
			e.mu.Unlock()
			return c, nil
		}
		if !e.dialing {
			// No dial in progress and no current conn: auth failed or ctx cancelled.
			err := e.dialErr
			e.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("no connection available for %q", e.name)
		}
		done := e.dialDone
		e.mu.Unlock()

		select {
		case <-done:
			// Loop back to check e.current.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// State returns the current connection state snapshot.
func (e *dialEntry) State() SessionState {
	e.mu.Lock()
	defer e.mu.Unlock()

	stateStr := "connecting"
	switch e.intState {
	case stateConnected:
		stateStr = "connected"
	case stateAuthFailed:
		// A permanent authentication rejection: the peer's pin does not match
		// ours, and the loop has stopped. "auth_failed" signals a permanent
		// configuration error, not a transient reconnect condition. Consumers
		// must not treat this as "connecting" and wait for recovery.
		stateStr = "auth_failed"
		// stateReconnecting and stateConnecting both project to "connecting":
		// from the consumer's perspective both mean "not healthy, may recover".
		// Do NOT add a "reconnecting" case here — it would be a sixth enum value,
		// breaking the five-value open enum defined in the status contract.
	}

	return SessionState{
		Name:       e.name,
		State:      stateStr,
		Transport:  transportDial,
		Since:      e.since,
		SSHPort:    e.sshPort,
		DockerPort: e.dockerPort,
	}
}

// Close cancels the entry's run-loop and closes the live connection.
func (e *dialEntry) Close(err error) {
	e.cancel()

	e.mu.Lock()
	conn := e.current
	cc := e.controlClient
	e.current = nil
	e.controlClient = nil
	e.mu.Unlock()

	if conn != nil {
		msg := "daemon shutting down"
		if err != nil {
			msg = err.Error()
		}
		_ = conn.CloseWithError(0, msg)
	}
	if cc != nil {
		_ = cc.Close()
	}

	// Wait for the run-loop to exit so we don't leak goroutines.
	<-e.runDone
}

// ---- helpers ----------------------------------------------------------------

// openControlStream opens the control gRPC stream on conn, classifying auth
// failures so the run-loop can stop retrying on a permanent rejection.
// The auth-rejection classification (checking both the control-open error and
// the connection close cause) is shared with the foreground connect path via
// tunnel.OpenControl so the logic lives in exactly one place.
func openControlStream(ctx context.Context, conn transport.Conn) (*control.Client, error) {
	return tunnel.OpenControl(ctx, conn, "quic-link daemon", control.OpenOpts{})
}
