package ipc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// defaultConnCap is the maximum number of concurrent socket connections the
// server accepts before backpressuring the accept loop. This is a non-
// contractual policy default tuned for a single-operator tool; it is not a
// per-release contract. The accept loop blocks on the semaphore when this
// limit is reached, preventing unbounded goroutine creation.
const defaultConnCap = 64

// defaultAttachCap is the maximum number of in-flight attach operations
// globally. Each attach maps to a real QUIC stream on a real session; this
// cap prevents the daemon's session pool from being flooded. Past the cap the
// server returns a clean "too many open tunnels" error. Also non-contractual.
const defaultAttachCap = 256

// StatusProvider supplies the snapshot bytes for a status RPC. The daemon
// injects a real implementation; tests inject a stub. Returning raw JSON bytes
// decouples the IPC package from the daemon's snapshot type so internal/ipc
// does not import internal/daemon.
type StatusProvider interface {
	// StatusJSON returns the JSON-encoded status snapshot ready to embed as
	// a CBOR raw message in the Response.Body field. The returned bytes MUST
	// be valid JSON.
	StatusJSON() ([]byte, error)
}

// DoctorProvider answers what only the daemon knows. probe is a label the
// caller has just looked up; the answer says whether that lookup reached the
// responder, which is the difference between "a name resolved" and "this
// machine's resolver is pointed here".
type DoctorProvider interface {
	DoctorJSON(probe string) ([]byte, error)
}

// RoutesProvider relays a live route-table query to a named server's agent
// over the control plane and reports the result. The daemon injects a real
// implementation that walks the session pool and the agent's control
// stream; tests inject a stub. Returning raw JSON bytes decouples this
// package from the daemon's own snapshot type, for the same reason
// StatusProvider does.
//
// When no live routes can be produced right now, RoutesJSON should return a
// *RoutesError naming exactly why not (a disabled server, one still
// connecting, one waiting for its agent, one that permanently failed
// authentication, an agent too old to answer this request, or a session
// that dropped mid-call) rather than one interchangeable failure — each of
// those is an expected, distinguishable outcome an operator needs to be
// able to tell apart, not a bug. Any other error is treated as unexpected
// and masked before it reaches the caller, the same way an unexpected
// doctor or status error already is.
type RoutesProvider interface {
	RoutesJSON(ctx context.Context, server string) ([]byte, error)
}

// VhostsProvider relays a live published-name query to a named server's agent
// and reports the result, on the same terms as RoutesProvider: raw JSON bytes so
// this package needs no knowledge of the daemon's snapshot type, and a
// *RoutesError when no listing can be produced right now, naming which of the
// situations it is. The error type is shared because the ways a live relay can
// fail do not depend on what was being asked for.
type VhostsProvider interface {
	VhostsJSON(ctx context.Context, server string) ([]byte, error)
}

// ExposeProvider asks a named server's agent to publish a hostname, over the
// control plane, and reports what happened. Like RoutesProvider it returns raw
// JSON so this package need not know the daemon's own reply type.
//
// The reply carries the port this machine is currently answering names on as
// well as what the agent published, because both are needed to name a working
// URL and only the daemon knows either. Asking twice would leave a gap in which
// the two could stop describing the same moment.
type ExposeProvider interface {
	ExposeJSON(ctx context.Context, server, host string, port int) ([]byte, error)
}

// WithdrawProvider relays a request to take back a published name, on the same
// terms as ExposeProvider: it changes the far side, so it is bounded in time and
// in what it may say, and every way it can fail short of success arrives as a
// *RoutesError naming which situation it is.
type WithdrawProvider interface {
	WithdrawJSON(ctx context.Context, server, host string) ([]byte, error)
}

// RoutesError is a RoutesProvider's way of saying "I already know exactly
// why, and exactly what process-exit-style status that reason belongs to."
// handleRPC relays Status and Msg verbatim when it sees this type, in place
// of the generic mask it applies to every other provider error.
type RoutesError struct {
	Status uint
	Msg    string
}

// Error implements the error interface.
func (e *RoutesError) Error() string { return e.Msg }

// routesErrorResponse turns a *RoutesError into the Response this socket
// actually sends, running its Msg through SanitizeAgentString first.
//
// A RoutesError's Msg is, at several of its construction sites in
// internal/daemon, a gRPC status message the connected agent worded itself
// (status.Convert(err).Message()) — text an authenticated, correctly-pinned
// peer chose, not text this build wrote. Being pinned proves which key
// answered a handshake; it says nothing about what that key's holder puts in
// a status message. Every one of handleRPC's four relay cases (routes,
// vhosts, withdraw, expose) turns a *RoutesError into a Response the same
// way, so that conversion happens exactly once, here, rather than once per
// case — a fifth relay added later gets this by construction instead of by
// remembering to call the sanitizer itself.
func routesErrorResponse(re *RoutesError) Response {
	return errorResponse(re.Status, SanitizeAgentString(re.Msg))
}

// routesRPCTimeout bounds how long the routes relay's own call to the agent
// may take, applied on top of whatever bound the daemon enforces internally
// on the control-plane call itself. It is generous headroom over that inner
// bound (5 seconds in the daemon package, which this package cannot import)
// so this is defense in depth against a caller-supplied context with no
// deadline of its own, not the primary timeout.
const routesRPCTimeout = 10 * time.Second

// routesBodyHeadroom reserves space for the CBOR envelope wrapped around the
// JSON route-table body (socket_schema, status, and the byte-string encoding
// of body itself) before the frame-size check on the body runs. It only
// needs to be larger than that envelope actually is — the body dominates the
// frame's total size — so a generous fixed margin is simpler than encoding
// the envelope twice just to measure it.
const routesBodyHeadroom = 512

// AttachPool looks up a pool entry for a named server and provides a live
// connection for the attach splice. The server implementation (in
// internal/daemon) satisfies both methods via its poolAttachAdapter.
type AttachPool interface {
	// EntryState returns the connection-state string for server, or an error
	// if the server is unknown or disabled. Used for fast-fail diagnostics
	// before calling OpenConn.
	EntryState(server string) (state string, err error)

	// OpenConn returns a live pooled connection for server, bounded-waiting
	// on an in-flight reconnect up to the pool's internal readiness deadline
	// (coalescing — never dialing a new connection). Returns the peer
	// pin-prefix (8 chars) for the audit line and an error when the session
	// is not ready. This is the readiness source of truth: a not-ready
	// session fails here rather than at EntryState so transient reconnects
	// are naturally absorbed.
	OpenConn(ctx context.Context, server string) (conn tunnel.StreamConn, pinPrefix string, err error)
}

// attachReadyTimeout is the maximum time handleAttach waits for the pool to
// provide a live connection when a reconnect is in progress. Five seconds is
// long enough to cover a single-flight reconnect already under way but short
// enough to give the operator a fast failure when the agent is genuinely down.
const attachReadyTimeout = 5 * time.Second

// ServerOpts carries optional tuning for the Server. Zero value uses the
// package-level defaults. These are policy settings, not contractual values.
type ServerOpts struct {
	// ConnCap is the maximum number of concurrent connections (default 64).
	// The accept loop blocks when this limit is reached.
	ConnCap int
	// AttachCap is the maximum number of in-flight attach operations (default 256).
	// Past the cap the server returns a "too many open tunnels" error.
	AttachCap int32
	// UID is the expected peer uid for the peer-cred check. 0 means "use the
	// current process's effective uid", which is the correct default for the
	// daemon. Tests can override this to match their own uid.
	UID int
}

// Server is the IPC socket server. It binds a unix socket, accepts
// connections, and dispatches each connection to a handler goroutine. The
// handler reads one Request and writes one Response (RPC path) or writes an
// attach-ack Response and then hands the connection to the splice logic (attach
// path — the splice is wired in a later slice; currently only the ack is sent).
//
// Server takes its dependencies (StatusProvider, AttachPool) via injection so
// internal/ipc does not import internal/daemon; the dependency points inward.
//
// Goroutine ownership: one goroutine per accepted connection, bounded by
// ConnCap via a semaphore. All goroutines exit when Close is called (which
// closes the listener, causing Accept to return). wg tracks in-flight handlers
// so Serve only returns after all handlers have finished.
type Server struct {
	path      string
	listener  net.Listener
	status    StatusProvider
	doctor    DoctorProvider
	routes    RoutesProvider
	vhosts    VhostsProvider
	expose    ExposeProvider
	withdraw  WithdrawProvider
	pool      AttachPool
	uid       int           // expected peer uid; checked at accept
	connSem   chan struct{} // semaphore bounding concurrent connections
	attachCap int32         // max in-flight attaches

	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool

	// inFlightAttaches counts active attach handlers (atomic).
	inFlightAttaches atomic.Int32
}

// NewServer creates a Server that will listen on path. Call Serve to start
// accepting connections. The socket file is created (mode 0600) and the
// containing directory must already exist at mode 0700. Call Close to stop
// accepting; in-flight handlers finish before Serve returns.
func NewServer(path string, status StatusProvider, pool AttachPool) *Server {
	return NewServerWithOpts(path, status, pool, ServerOpts{})
}

// NewServerWithOpts creates a Server with custom tuning. Use this in tests to
// lower the caps for deterministic testing. Zero fields in opts use defaults.
func NewServerWithOpts(path string, status StatusProvider, pool AttachPool, opts ServerOpts) *Server {
	connCap := opts.ConnCap
	if connCap <= 0 {
		connCap = defaultConnCap
	}
	attachCap := opts.AttachCap
	if attachCap <= 0 {
		attachCap = defaultAttachCap
	}
	uid := opts.UID
	if uid == 0 {
		uid = os.Getuid()
	}
	return &Server{
		path:      path,
		status:    status,
		pool:      pool,
		uid:       uid,
		connSem:   make(chan struct{}, connCap),
		attachCap: attachCap,
	}
}

// Listen binds the unix socket. It must be called before Serve.
// After Listen returns, the socket file exists and is ready to accept.
func (s *Server) Listen() error {
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("ipc: listen %s: %w", s.path, err)
	}
	s.listener = ln
	return nil
}

// Serve accepts connections on the bound socket until ctx is cancelled or the
// server is closed. It is the caller's responsibility to call Listen before
// Serve. Serve blocks until all in-flight handlers have finished after the
// accept loop exits.
func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		return fmt.Errorf("ipc: Serve called before Listen")
	}

	// Close the listener when ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		// Acquire a slot in the connection semaphore before accepting.
		// This blocks when the cap is reached, providing backpressure
		// rather than spawning unbounded goroutines.
		acquired := false
		select {
		case s.connSem <- struct{}{}:
			acquired = true
		case <-ctx.Done():
		}
		if !acquired {
			break
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Release the slot we just acquired (no goroutine was spawned).
			<-s.connSem
			s.mu.Lock()
			wasClosed := s.closed
			s.mu.Unlock()
			if wasClosed || errors.Is(err, net.ErrClosed) {
				break
			}
			slog.Warn("ipc: accept error", "role", "daemon", "err", err)
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			// connSem slot: released early (via releaseConn) on the OK attach path
			// so a long-lived splice does not hold the slot for hours. The Once
			// guarantees exactly-once release on all paths.
			var releaseOnce sync.Once
			releaseConn := func() {
				releaseOnce.Do(func() { <-s.connSem })
			}
			defer releaseConn() // fallback: releases on RPC/error paths
			s.handleConn(ctx, c, releaseConn)
		}(conn)
	}

	s.wg.Wait()
	return nil
}

// Close stops accepting new connections. In-flight handlers are allowed to
// finish; Serve returns only after all of them exit. Idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleConn performs the peer-cred check, reads one Request, and dispatches.
// The conn is always closed when the handler returns. releaseConn releases the
// connSem slot; it is a sync.Once so callers may invoke it early (before a
// long splice) without worrying about double-release.
func (s *Server) handleConn(ctx context.Context, conn net.Conn, releaseConn func()) {
	defer conn.Close()

	// Peer-cred same-uid check at accept time. This is defense-in-depth on
	// top of the 0700/0600 filesystem permissions. It rejects connections from
	// processes running as a different uid, surviving a directory-mode mistake
	// on the socket parent. It does NOT raise the security ceiling against a
	// same-uid adversary — that is the accepted single-operator boundary.
	puid, err := peerUID(conn)
	if err != nil {
		slog.Warn("ipc: peer-cred check failed; rejecting connection",
			"role", "daemon", "err", err)
		_ = writeResponse(conn, errorResponse(1, "peer-cred check failed"))
		return
	}
	if int(puid) != s.uid {
		slog.Warn("ipc: peer uid mismatch; rejecting connection",
			"role", "daemon", "peer_uid", puid, "expected_uid", s.uid)
		_ = writeResponse(conn, errorResponse(1,
			fmt.Sprintf("peer uid %d not authorized (expected %d)", puid, s.uid)))
		return
	}

	// Apply the opening-read deadline to guard against a slow or silent
	// client that connects but never sends a frame. The deadline is cleared
	// after the request is read so a long-running splice is not interrupted.
	if err := conn.SetReadDeadline(time.Now().Add(openReadDeadline)); err != nil {
		slog.Debug("ipc: set read deadline", "role", "daemon", "err", err)
		return
	}

	req, err := readRequest(conn)
	if err != nil {
		slog.Debug("ipc: read request", "role", "daemon", "err", err)
		if errors.Is(err, ErrFrameTooLarge) {
			_ = writeResponse(conn, errorResponse(1, err.Error()))
		}
		// For other errors (EOF, timeout, version mismatch) nothing useful can
		// be sent — the frame header was not fully readable.
		return
	}

	// Clear the deadline so subsequent operations are not time-bounded.
	_ = conn.SetReadDeadline(time.Time{})

	// Schema validation fails closed: an unknown or zero schema gets a framed
	// error and no action is taken. The client identifies the daemon's schema
	// from the Response.SocketSchema field in the error reply.
	if req.SocketSchema != SocketSchema {
		slog.Warn("ipc: socket schema mismatch",
			"role", "daemon",
			"client_schema", req.SocketSchema,
			"daemon_schema", SocketSchema,
		)
		_ = writeResponse(conn, schemaMismatchResponse(req.SocketSchema))
		return
	}

	switch req.Kind {
	case "rpc":
		s.handleRPC(ctx, conn, req)
	case "attach":
		s.handleAttach(ctx, conn, req, releaseConn)
	default:
		slog.Debug("ipc: unknown kind", "role", "daemon", "kind", req.Kind)
		_ = writeResponse(conn, errorResponse(1, fmt.Sprintf("unknown kind %q", req.Kind)))
	}
}

// relayCall describes one live relay to a remote agent: what to call, and
// this case's own wording for every place that wording legitimately differs
// from its siblings. relay itself owns everything that must NOT differ —
// the timeout applied to the call, the *RoutesError-to-response translation
// (sanitized through routesErrorResponse), the frame-size bound checked
// against the reply, and the final write. A relay case cannot reach the
// write without passing through that sequence, because relay is the only
// path to it: there is no way to add a fifth relay that calls writeResponse
// directly and skips the bound or the sanitization, short of not using this
// type at all. That is the entire point of it existing.
type relayCall struct {
	// method names this relay for log lines (matches req.Method, e.g. "routes").
	method string
	// server is the target server name, already validated non-empty by the caller.
	server string
	// call performs the provider round trip. relay supplies it a context
	// already bounded by routesRPCTimeout; call does not need to apply its
	// own bound.
	call func(ctx context.Context) ([]byte, error)
	// genericErrMsg is the response text when call fails with an error that
	// is not a *RoutesError — an unexpected local failure, masked the same
	// way "doctor" and "status" mask theirs.
	genericErrMsg string
	// tooLargeLogMsg is the slog message logged when the reply cannot fit
	// this socket's frame.
	tooLargeLogMsg string
	// tooLargeRespMsg builds this case's own wording for that same refusal,
	// given the body length that overflowed.
	tooLargeRespMsg func(bodyLen int) string
}

// relay runs one live agent relay to completion and writes exactly one
// Response. Every one of handleRPC's relay cases (routes, vhosts, withdraw,
// expose) funnels through here rather than repeating the sequence inline,
// so a reply that is too large for this socket's frame is always caught
// before the write, and a *RoutesError's Msg always crosses the same
// sanitizing boundary before it reaches the caller — on every relay that
// exists today, and on any relay added after this one, whether or not
// whoever adds it remembers either rule.
func (s *Server) relay(ctx context.Context, conn net.Conn, rc relayCall) {
	rctx, cancel := context.WithTimeout(ctx, routesRPCTimeout)
	body, err := rc.call(rctx)
	cancel()
	if err != nil {
		var re *RoutesError
		if errors.As(err, &re) {
			// The provider already knows exactly why and exactly what status
			// that belongs to — relay both, through the same sanitizing
			// boundary every RoutesError crosses (see routesErrorResponse),
			// rather than replacing a distinguishable reason with a generic
			// one.
			_ = writeResponse(conn, routesErrorResponse(re))
			return
		}
		slog.Warn("ipc: relay "+rc.method, "role", "daemon", "server", rc.server, "err", err)
		_ = writeResponse(conn, errorResponse(1, rc.genericErrMsg))
		return
	}
	// The provider replies with JSON, which costs materially more bytes per
	// field than the protobuf wire format the control-plane call itself was
	// capped at (repeated key names, quoting). A reply that fit under that
	// cap can still, once re-encoded as JSON, exceed this socket's own frame
	// cap — checked explicitly here, before attempting the write, so that
	// case gets a named error response instead of writeFrame silently
	// refusing the write later and leaving the caller with a bare socket
	// error and no response frame at all.
	if len(body) > maxFrameSize-routesBodyHeadroom {
		slog.Warn(rc.tooLargeLogMsg, "role", "daemon", "server", rc.server, "body_bytes", len(body))
		_ = writeResponse(conn, errorResponse(1, rc.tooLargeRespMsg(len(body))))
		return
	}
	_ = writeResponse(conn, okResponse(body))
}

// handleRPC dispatches method-specific logic and writes a single Response.
// ctx is the server's own lifetime context (cancelled on shutdown); it bounds
// each relay case's call (via relay) so a wedged agent cannot hold a handler
// open indefinitely. An unrecognized req.Method falls through to the default
// case below and degrades cleanly — no schema change is needed to add a
// method here, and none is needed to reject one this daemon does not know.
func (s *Server) handleRPC(ctx context.Context, conn net.Conn, req Request) {
	slog.Debug("ipc: rpc", "role", "daemon", "method", req.Method)
	switch req.Method {
	case "doctor":
		// A separate method with a separate shape. The status response is a
		// contract other programs read; diagnosis output is not, and mixing
		// them would freeze something that still needs to change.
		//
		// The provider is read once, here, under the lock (getDoctor), rather
		// than as a direct field access repeated through the rest of this
		// case — SetDoctor can be called concurrently from another goroutine,
		// and a direct field read racing with that write is exactly the
		// defect this snapshot avoids.
		doctor := s.getDoctor()
		if doctor == nil {
			_ = writeResponse(conn, errorResponse(1, "this daemon does not answer diagnosis requests"))
			return
		}
		snap, err := doctor.DoctorJSON(req.Meta["probe"])
		if err != nil {
			slog.Warn("ipc: build doctor snapshot", "role", "daemon", "err", err)
			_ = writeResponse(conn, errorResponse(1, "internal error building the report"))
			return
		}
		_ = writeResponse(conn, okResponse(snap))

	case "status":
		snap, err := s.status.StatusJSON()
		if err != nil {
			slog.Warn("ipc: build status snapshot", "role", "daemon", "err", err)
			_ = writeResponse(conn, errorResponse(1, "internal error building status"))
			return
		}
		_ = writeResponse(conn, okResponse(snap))

	case "routes":
		// A live relay to a remote agent, not a local read — the server name
		// travels in req.Server, the same field handleAttach already uses to
		// carry the target server, rather than a new field on Request just
		// for this one method.
		//
		// This handler does not release its connSem slot early the way
		// handleAttach does for a long splice: relay's own call to the agent
		// is bounded by routesRPCTimeout (10s), so holding the slot for that
		// long is a deliberate, bounded trade-off, not an oversight — there
		// is no unbounded hold to guard against here.
		//
		// The provider is read once, under the lock (getRoutes), for the
		// same reason as the "doctor" case above: SetRoutes can be called
		// from another goroutine while this request is in flight.
		routes := s.getRoutes()
		if routes == nil {
			_ = writeResponse(conn, errorResponse(1, "this daemon does not answer route relay requests"))
			return
		}
		if req.Server == "" {
			_ = writeResponse(conn, errorResponse(1, "routes: server name is required"))
			return
		}
		s.relay(ctx, conn, relayCall{
			method: "routes",
			server: req.Server,
			call: func(rctx context.Context) ([]byte, error) {
				return routes.RoutesJSON(rctx, req.Server)
			},
			genericErrMsg:  "internal error relaying routes",
			tooLargeLogMsg: "ipc: relay routes: route table too large for the local socket frame",
			tooLargeRespMsg: func(n int) string {
				return fmt.Sprintf(
					"server %q's route table is too large to relay over the local socket (%d bytes as JSON); this is a local IPC limit, not a problem with the agent",
					req.Server, n)
			},
		})

	case "vhosts":
		// The read counterpart of publishing a name: a live relay to the agent,
		// with the server name travelling in req.Server as it does for the route
		// listing. It holds its connection slot for the whole relay for the same
		// reason — the call to the agent is bounded, so the hold is bounded too.
		//
		// The provider is read once, under the lock (getVhosts); see the
		// "doctor" case above for why.
		vhosts := s.getVhosts()
		if vhosts == nil {
			_ = writeResponse(conn, errorResponse(1, "this daemon does not answer published-name requests"))
			return
		}
		if req.Server == "" {
			_ = writeResponse(conn, errorResponse(1, "vhosts: server name is required"))
			return
		}
		s.relay(ctx, conn, relayCall{
			method: "vhosts",
			server: req.Server,
			call: func(vctx context.Context) ([]byte, error) {
				return vhosts.VhostsJSON(vctx, req.Server)
			},
			genericErrMsg:  "internal error relaying published names",
			tooLargeLogMsg: "ipc: relay vhosts: name table too large for the local socket frame",
			tooLargeRespMsg: func(n int) string {
				return fmt.Sprintf(
					"server %q publishes too many names to relay over the local socket (%d bytes as JSON); this is a local IPC limit, not a problem with the agent",
					req.Server, n)
			},
		})

	case "withdraw":
		// Changes the far side, so like publishing it is bounded in time and the
		// name is checked for shape here, before anything is asked of the agent:
		// a local mistake is answered locally.
		//
		// The provider is read once, under the lock (getWithdraw); see the
		// "doctor" case above for why.
		withdraw := s.getWithdraw()
		if withdraw == nil {
			_ = writeResponse(conn, errorResponse(1, "this daemon does not answer withdraw requests"))
			return
		}
		if req.Server == "" {
			_ = writeResponse(conn, errorResponse(1, "withdraw: server name is required"))
			return
		}
		whost := req.Meta["host"]
		if whost == "" {
			_ = writeResponse(conn, errorResponse(1, "withdraw: name is required"))
			return
		}
		s.relay(ctx, conn, relayCall{
			method: "withdraw",
			server: req.Server,
			call: func(wctx context.Context) ([]byte, error) {
				return withdraw.WithdrawJSON(wctx, req.Server, whost)
			},
			genericErrMsg:  "internal error withdrawing a name",
			tooLargeLogMsg: "ipc: relay withdraw: reply too large for the local socket",
			// WithdrawSnapshot carries three agent-worded strings (Host,
			// ShadowedBy, ShadowedByAddress), so its JSON encoding can
			// exceed this socket's frame the same way a route or vhost
			// listing can — refused by name here for the same reason those
			// two siblings are, rather than a bare socket error
			// indistinguishable from a dead daemon.
			tooLargeRespMsg: func(n int) string {
				return fmt.Sprintf(
					"server %q sent a withdrawal reply too large to relay over the local socket (%d bytes as JSON); "+
						"this is a local IPC limit, not a problem with the name", req.Server, n)
			},
		})

	case "expose":
		// A live relay that changes something on the far side, so unlike the
		// read above it is bounded not only in time but in what it may say:
		// the name and port are checked for shape here, before a request is
		// made of the agent, so a local mistake is answered locally.
		//
		// Like the read above, this handler holds its connection slot for the
		// whole relay rather than releasing it early: the call to the agent is
		// bounded by the same timeout, so the hold is a bounded, deliberate
		// trade-off rather than something to guard against.
		//
		// The provider is read once, under the lock (getExpose); see the
		// "doctor" case above for why.
		expose := s.getExpose()
		if expose == nil {
			_ = writeResponse(conn, errorResponse(1, "this daemon does not answer publish requests"))
			return
		}
		if req.Server == "" {
			_ = writeResponse(conn, errorResponse(1, "expose: server name is required"))
			return
		}
		host := req.Meta["host"]
		if host == "" {
			_ = writeResponse(conn, errorResponse(1, "expose: a name to publish is required"))
			return
		}
		port, perr := strconv.Atoi(req.Meta["port"])
		if perr != nil || port < 1 || port > 65535 {
			_ = writeResponse(conn, errorResponse(1, fmt.Sprintf(
				"expose: %q is not a port between 1 and 65535", req.Meta["port"])))
			return
		}
		s.relay(ctx, conn, relayCall{
			method: "expose",
			server: req.Server,
			call: func(ectx context.Context) ([]byte, error) {
				return expose.ExposeJSON(ectx, req.Server, host, port)
			},
			genericErrMsg:  "internal error relaying a publish request",
			tooLargeLogMsg: "ipc: relay expose: reply too large for the local socket",
			// The reply carries a name the agent chose, and JSON escaping
			// can make a hostile one several times longer than the control
			// plane's own cap allowed — refused by name here for the same
			// reason, rather than a bare socket error with no response at
			// all.
			tooLargeRespMsg: func(n int) string {
				return fmt.Sprintf(
					"server %q sent a reply too large to relay over the local socket (%d bytes as JSON); "+
						"this is a local IPC limit, not a problem with the name", req.Server, n)
			},
		})

	default:
		_ = writeResponse(conn, errorResponse(1, fmt.Sprintf("unknown method %q", req.Method)))
	}
}

// handleAttach validates the attach request, acquires a live pooled connection,
// sends an ack to the caller, and then bidirectionally splices the socket
// connection to a QUIC stream for the named target. The in-flight-attach counter
// is held for the full duration of the splice so the cap accurately reflects
// active tunnels. The connSem slot is released early (via releaseConn) after the
// ack so a long-lived splice does not starve concurrent status RPCs.
func (s *Server) handleAttach(ctx context.Context, conn net.Conn, req Request, releaseConn func()) {
	if req.Server == "" {
		_ = writeResponse(conn, errorResponse(1, "attach: server name is required"))
		return
	}
	if req.Target == "" {
		_ = writeResponse(conn, errorResponse(1, "attach: target name is required"))
		return
	}

	// Enforce the global in-flight-attach cap before opening a QUIC stream.
	// This prevents a flood of socket connections from exhausting QUIC streams
	// across the fleet. The cap is non-contractual and tunable via NewServerWithOpts.
	current := s.inFlightAttaches.Add(1)
	if current > s.attachCap {
		s.inFlightAttaches.Add(-1)
		slog.Warn("ipc: attach cap reached; rejecting attach",
			"role", "daemon",
			"in_flight", current,
			"cap", s.attachCap,
		)
		_ = writeResponse(conn, errorResponse(1, "too many open tunnels; try again later"))
		return
	}
	defer s.inFlightAttaches.Add(-1)

	// Fast-fail path: check EntryState first so unknown/disabled servers get a
	// crisp message rather than waiting the full readiness timeout. OpenConn is
	// still the readiness source of truth for the connecting state.
	if _, err := s.pool.EntryState(req.Server); err != nil {
		slog.Debug("ipc: attach: unknown/disabled server", "role", "daemon", "server", req.Server, "err", err)
		_ = writeResponse(conn, errorResponse(3, fmt.Sprintf("server %q: %v", req.Server, err)))
		return
	}

	// Wait up to attachReadyTimeout for a live pooled connection. A session
	// that is reconnecting is absorbed here rather than failing immediately,
	// as long as it completes within the deadline.
	octx, cancel := context.WithTimeout(ctx, attachReadyTimeout)
	poolConn, pinPrefix, err := s.pool.OpenConn(octx, req.Server)
	cancel()
	if err != nil {
		slog.Debug("ipc: attach: pool not ready", "role", "daemon", "server", req.Server, "err", err)
		_ = writeResponse(conn, errorResponse(3, fmt.Sprintf("server %q: not ready: %v", req.Server, err)))
		return
	}

	// Derive the reqid for cross-host log correlation.
	reqid := req.Meta["reqid"]
	if reqid == "" {
		reqid = tunnel.NewReqID()
	}

	start := time.Now()
	tunnel.LogAttach(req.Server, req.Target, reqid, pinPrefix, start, false)
	defer tunnel.LogAttach(req.Server, req.Target, reqid, pinPrefix, start, true)

	// relayAck writes the ack to the socket caller and, on success, releases
	// the connSem slot early so a long splice does not starve concurrent RPCs.
	// The Once in releaseConn guarantees the slot is released exactly once
	// even if this closure is called and then the defer in the accept goroutine
	// fires again later.
	//
	// resp.Msg on a non-OK ack is the agent's own wording, carried here over
	// the QUIC wire from wherever the agent's route table refused the attach —
	// the same kind of far-end-worded text a RoutesError carries, and it
	// crosses this socket into the CLI's stderr the same way. Sanitized for
	// the same reason routesErrorResponse sanitizes a RoutesError's Msg.
	relayAck := func(resp proto.Response) error {
		var writeErr error
		if resp.Status == proto.StatusOK {
			writeErr = writeResponse(conn, okResponse(nil))
		} else {
			writeErr = writeResponse(conn, errorResponse(
				uint(proto.ExitCodeForStatus(resp.Status)), SanitizeAgentString(resp.Msg)))
		}
		if writeErr != nil {
			return writeErr
		}
		if resp.Status == proto.StatusOK {
			// Release the connSem slot before entering the long splice so
			// status RPCs are not starved by tunnel-idle time.
			releaseConn()
		}
		return nil
	}

	// DoAttach opens one stream, writes the header, waits for the response,
	// calls relayAck, and on success runs the bidirectional splice. It never
	// dials. conn (the unix socket) is the local leg; poolConn is the QUIC leg.
	if err := tunnel.DoAttach(ctx, poolConn, conn, req.Target, reqid, relayAck); err != nil {
		slog.Debug("ipc: attach splice ended", "role", "daemon", "server", req.Server, "target", req.Target, "err", err)
	}
}

// SetDoctor supplies the diagnosis provider. It is set separately rather than
// passed to the constructor because a daemon without one is a working daemon —
// it simply says so when asked — and every existing caller stays as it was.
//
// Guarded by s.mu, the same mutex Serve/Close already use: every production
// caller sets providers once, before Serve starts, but nothing in the type
// enforced that, and the request-handling reads in handleRPC run concurrently
// with each other once Serve is accepting connections. The mutex makes a
// late or concurrent call to this method safe rather than merely unlikely to
// be exercised. See getDoctor for the matching read.
func (s *Server) SetDoctor(d DoctorProvider) {
	s.mu.Lock()
	s.doctor = d
	s.mu.Unlock()
}

// SetExpose supplies the publish-relay provider. Set separately for the same
// reason SetRoutes is: a daemon without one answers every other method
// perfectly well and refuses this one by name. Guarded by s.mu; see SetDoctor.
func (s *Server) SetExpose(e ExposeProvider) {
	s.mu.Lock()
	s.expose = e
	s.mu.Unlock()
}

// SetWithdraw installs the name-withdrawal relay, on the same terms as
// SetExpose. Guarded by s.mu; see SetDoctor.
func (s *Server) SetWithdraw(w WithdrawProvider) {
	s.mu.Lock()
	s.withdraw = w
	s.mu.Unlock()
}

// SetRoutes supplies the route-relay provider. Like SetDoctor, it is set
// separately rather than passed to the constructor because a daemon without
// one is a working daemon for every other RPC — it simply refuses the
// "routes" method with a clear message until this is called. Guarded by
// s.mu; see SetDoctor.
func (s *Server) SetRoutes(r RoutesProvider) {
	s.mu.Lock()
	s.routes = r
	s.mu.Unlock()
}

// SetVhosts installs the published-name relay, on the same terms as
// SetRoutes. Guarded by s.mu; see SetDoctor.
func (s *Server) SetVhosts(v VhostsProvider) {
	s.mu.Lock()
	s.vhosts = v
	s.mu.Unlock()
}

// getDoctor, getExpose, getWithdraw, getRoutes and getVhosts read the
// corresponding provider field under s.mu and return it. handleRPC calls
// these once per request at the top of each case, rather than reading the
// field directly, so the value it acts on for the rest of that case is a
// consistent snapshot taken under the lock — not a value that could still
// change underneath it mid-request. A provider swapped in immediately after
// the snapshot is taken affects only the next request, never this one.
func (s *Server) getDoctor() DoctorProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doctor
}

func (s *Server) getExpose() ExposeProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expose
}

func (s *Server) getWithdraw() WithdrawProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withdraw
}

func (s *Server) getRoutes() RoutesProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes
}

func (s *Server) getVhosts() VhostsProvider {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vhosts
}
