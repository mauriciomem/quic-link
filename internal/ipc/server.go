package ipc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
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

// AttachPool looks up a pool entry for a named server so the attach handler
// can validate that the server exists and report its current state. The full
// splice (socket conn → QUIC stream) is wired in a later slice; currently the
// pool is consulted only to produce a meaningful ack status.
type AttachPool interface {
	// EntryState returns the connection-state string for server, or an error
	// if the server is unknown or disabled.
	EntryState(server string) (state string, err error)
}

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
			defer func() {
				// Release the semaphore slot when the handler finishes.
				<-s.connSem
			}()
			s.handleConn(c)
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
// The conn is always closed when the handler returns.
func (s *Server) handleConn(conn net.Conn) {
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
		s.handleRPC(conn, req)
	case "attach":
		s.handleAttach(conn, req)
	default:
		slog.Debug("ipc: unknown kind", "role", "daemon", "kind", req.Kind)
		_ = writeResponse(conn, errorResponse(1, fmt.Sprintf("unknown kind %q", req.Kind)))
	}
}

// handleRPC dispatches method-specific logic and writes a single Response.
func (s *Server) handleRPC(conn net.Conn, req Request) {
	slog.Debug("ipc: rpc", "role", "daemon", "method", req.Method)
	switch req.Method {
	case "status":
		snap, err := s.status.StatusJSON()
		if err != nil {
			slog.Warn("ipc: build status snapshot", "role", "daemon", "err", err)
			_ = writeResponse(conn, errorResponse(1, "internal error building status"))
			return
		}
		_ = writeResponse(conn, okResponse(snap))
	default:
		_ = writeResponse(conn, errorResponse(1, fmt.Sprintf("unknown method %q", req.Method)))
	}
}

// handleAttach validates the attach request and returns an ack. The global
// in-flight attach cap is checked first; if it is exceeded the connection
// receives a clean "too many open tunnels" error without opening a QUIC stream.
//
// The full socket→QUIC splice is wired in a later slice; this stub responds
// immediately so the CLI can distinguish "server found and connected" from
// "server unknown/not ready" via the Response.Status field.
//
// Splice wiring point: when the splice is implemented, it will be called here
// after a status-0 Response has been written, handing conn and the opened QUIC
// stream to tunnel.Pipe. The in-flight counter must remain incremented for the
// duration of the splice.
func (s *Server) handleAttach(conn net.Conn, req Request) {
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
	// across the fleet. The cap is non-contractual and tunable.
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

	state, err := s.pool.EntryState(req.Server)
	if err != nil {
		slog.Debug("ipc: attach lookup", "role", "daemon", "server", req.Server, "err", err)
		_ = writeResponse(conn, errorResponse(3, fmt.Sprintf("server %q: %v", req.Server, err)))
		return
	}

	if state != "connected" {
		_ = writeResponse(conn, errorResponse(3, fmt.Sprintf("server %q is %s; not ready", req.Server, state)))
		return
	}

	// Send the attach-ack. The splice will be wired here in the next slice
	// (1b.1c): after this Response the conn becomes the local leg of a
	// tunnel.Pipe call connecting it to an opened QUIC stream.
	_ = writeResponse(conn, okResponse(nil))
	// splice seam: tunnel.Pipe(conn, quicStream) goes here.
}
