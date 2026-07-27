package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// clientVersion is advertised in the control stream header meta.
// TODO: replace with the build version once it is wired through.
const clientVersion = "quic-link client"

// Forward binds a local listener to a logical agent target. Connect opens one
// QUIC stream per accepted connection on Listener, naming Target.
type Forward struct {
	Listener net.Listener
	Target   string
}

// ConnectOpts carries optional parameters for Connect. All fields are optional;
// the zero value is valid and produces the same behaviour as a bare Connect call.
type ConnectOpts struct {
	// KeyCreated is an RFC3339 UTC string recording when the client's identity
	// key was generated. When non-empty it is forwarded to the control-stream
	// header so the agent can log a rotation reminder for over-age client keys.
	// Advisory only — never gates a connection.
	KeyCreated string
}

// Connect forwards each TCP connection accepted on every Forward's listener to
// the QUIC agent at serverAddr via t as a single QUIC stream naming that
// forward's logical target. All forwards share one persistent QUIC connection,
// re-established automatically if it drops (capped exponential backoff). One
// accept-loop goroutine runs per forward; the first non-ctx accept error
// cancels the others and is returned. All listeners are closed on ctx.Done.
// Runs until ctx is cancelled or a listener fails.
//
// The QUIC session is established eagerly at startup: if the agent is
// unreachable or rejects the pin, Connect returns the classified error
// immediately (before the accept loops start) so the caller can surface the
// correct exit code without waiting for the first forwarded connection.
func Connect(
	ctx context.Context,
	t transport.Transport,
	serverAddr string,
	forwards []Forward,
	opts ...ConnectOpts,
) error {
	var opt ConnectOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	mgr := &connManager{t: t, serverAddr: serverAddr, keyCreated: opt.KeyCreated}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Dial eagerly so an unreachable or mis-pinned agent surfaces at startup
	// rather than on the first forwarded connection.
	if _, err := mgr.Establish(ctx); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		for _, f := range forwards {
			f.Listener.Close()
		}
	}()

	errCh := make(chan error, len(forwards))
	var wg sync.WaitGroup
	for _, f := range forwards {
		wg.Add(1)
		go func(f Forward) {
			defer wg.Done()
			errCh <- acceptLoop(ctx, mgr, f)
		}(f)
	}

	// First loop to exit wins; cancel the rest and drain before returning.
	err := <-errCh
	cancel()
	wg.Wait()
	// Send a CONNECTION_CLOSE to the peer instead of waiting for the idle
	// timeout. Without this the agent would wait up to 60s before detecting
	// that the client is gone.
	mgr.Close()
	return err
}

// acceptLoop accepts local connections on f.Listener and forwards each to the
// agent as a stream naming f.Target. A failure caused by ctx cancellation is
// reported as ctx.Err().
func acceptLoop(ctx context.Context, mgr *connManager, f Forward) error {
	for {
		tcpConn, err := f.Listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("local accept (%s): %w", f.Target, err)
			}
		}
		go forwardTCP(ctx, mgr, tcpConn, f.Target)
	}
}

// forwardTCP opens a QUIC stream to the agent, stamps the protocol header
// (including a per-stream correlation id in Meta["reqid"]), waits for a
// success response, and then proxies data between tcpConn and the stream.
// It retries the stream open once if the first attempt fails (handles the race
// where the QUIC connection dropped between get and use).
func forwardTCP(ctx context.Context, mgr *connManager, tcpConn net.Conn, target string) {
	defer tcpConn.Close()

	reqid := NewReqID()
	start := time.Now()
	slog.Info("session opened", "local", tcpConn.RemoteAddr(), "target", target, "reqid", reqid)
	defer func() {
		slog.Info("session closed",
			"local", tcpConn.RemoteAddr(),
			"duration", time.Since(start).Round(time.Millisecond),
			"reqid", reqid,
		)
	}()

	conn, err := mgr.get(ctx)
	if err != nil {
		slog.Warn("get QUIC conn", "err", err, "reqid", reqid)
		return
	}

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		// Connection may have died since we got it; invalidate and retry once.
		mgr.invalidate(conn)
		conn, err = mgr.get(ctx)
		if err != nil {
			slog.Warn("get QUIC conn (retry)", "err", err, "reqid", reqid)
			return
		}
		stream, err = conn.OpenStream(ctx)
		if err != nil {
			slog.Warn("open QUIC stream", "err", err, "reqid", reqid)
			return
		}
	}

	// Name a logical target; never an ip:port. Include the reqid so the
	// agent can log it and both sides can be correlated by a single grep.
	hdr := proto.Header{
		Kind:   proto.KindTCP,
		Target: target,
		Meta:   map[string]string{"reqid": reqid},
	}
	if err := proto.WriteHeader(stream, hdr); err != nil {
		slog.Warn("write header", "err", err, "target", target, "reqid", reqid)
		stream.Reset(proto.StreamResetCode)
		resetConn(tcpConn)
		return
	}

	// Wait for the response (10s deadline) before sending any payload.
	resp, err := awaitResponse(ctx, stream, proto.ResponseDeadline)
	if err != nil {
		slog.Warn("await response", "err", err, "target", target, "reqid", reqid)
		resetConn(tcpConn) // stream already reset by awaitResponse
		return
	}

	slog.Debug("stream header exchange complete",
		"kind", proto.KindTCP,
		"target", target,
		"reqid", reqid,
		"status", resp.Status.String(),
	)

	if resp.Status != proto.StatusOK {
		// Surface the agent's message verbatim.
		slog.Warn("agent refused stream",
			"target", target,
			"status", uint(resp.Status),
			"status_name", resp.Status.String(),
			"msg", resp.Msg,
			"reqid", reqid,
		)
		stream.Reset(proto.StreamResetCode)
		resetConn(tcpConn)
		return
	}

	// pipe closes tcpConn (a) and stream (b) when done.
	pipe(tcpConn, stream)
}

// AwaitResponse reads the agent's response frame, enforcing the response
// deadline. On timeout, context cancellation, or a read error it resets the
// stream (which also unblocks the read goroutine) and returns an error.
// It is exported so callers outside this package (e.g. a stdio bridge in cmd/)
// can reuse the same await behaviour without duplicating the timer/select logic.
func AwaitResponse(ctx context.Context, stream transport.Stream, d time.Duration) (proto.Response, error) {
	return awaitResponse(ctx, stream, d)
}

// awaitResponse is the unexported implementation.
func awaitResponse(ctx context.Context, stream transport.Stream, d time.Duration) (proto.Response, error) {
	type result struct {
		resp proto.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := proto.ReadResponse(stream)
		ch <- result{resp, err}
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case res := <-ch:
		if res.err != nil {
			stream.Reset(proto.StreamResetCode)
			return proto.Response{}, res.err
		}
		return res.resp, nil
	case <-timer.C:
		stream.Reset(proto.StreamResetCode)
		return proto.Response{}, fmt.Errorf("timed out after %s waiting for response", d)
	case <-ctx.Done():
		stream.Reset(proto.StreamResetCode)
		return proto.Response{}, ctx.Err()
	}
}

// connManager maintains a single persistent QUIC connection to serverAddr,
// together with the session's control stream (opened right after each dial;
// its presence satisfies the agent's control-open deadline and its closure
// signals session death). Concurrent callers share one in-flight dial via a
// single-flight mechanism.
type connManager struct {
	mu            sync.Mutex
	current       transport.Conn
	controlClient *control.Client
	dialErr       error
	dialing       bool
	dialDone      chan struct{}
	t             transport.Transport
	serverAddr    string
	// keyCreated is included in the control-stream header when non-empty so
	// the agent can log a rotation reminder for over-age client keys.
	// It is set once at construction and never mutated.
	keyCreated string
}

// Establish performs the eager initial dial and control-stream open before any
// traffic flows, so an unreachable or mis-pinned agent is reported at startup
// rather than on the first forwarded connection. On success the live session is
// recorded and its drop-monitor started (subsequent drops re-dial lazily on the
// next request, exactly as before). The returned error is already classified
// (peer-unreachable or authentication-failure) for exit-code mapping.
func (m *connManager) Establish(ctx context.Context) (transport.Conn, error) {
	conn, err := m.t.Dial(ctx, m.serverAddr)
	if err != nil {
		return nil, err
	}
	cclient, err := openControlAndRecord(ctx, m, conn)
	if err != nil {
		return nil, err
	}
	startDropMonitor(m, conn, cclient)
	slog.Info("connected to server", "server", m.serverAddr)
	return conn, nil
}

// get returns the current QUIC connection or dials a new one. If a dial is
// already in progress, callers block on the shared result. Subsequent calls
// after Establish use this lazy re-dial path on connection drop.
func (m *connManager) get(ctx context.Context) (transport.Conn, error) {
	m.mu.Lock()
	if m.current != nil {
		c := m.current
		m.mu.Unlock()
		return c, nil
	}
	if m.dialing {
		done := m.dialDone
		m.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m.mu.Lock()
		c, err := m.current, m.dialErr
		m.mu.Unlock()
		if c == nil && err == nil {
			err = fmt.Errorf("dial completed with no connection")
		}
		return c, err
	}
	// We are the goroutine that will drive the dial.
	m.dialing = true
	m.dialDone = make(chan struct{})
	done := m.dialDone
	m.mu.Unlock()

	conn, dialErr := m.dialWithBackoff(ctx)
	var cclient *control.Client
	if dialErr == nil {
		cclient, dialErr = openControlAndRecord(ctx, m, conn)
		if dialErr != nil {
			conn = nil
		}
	}

	m.mu.Lock()
	m.dialErr = dialErr
	if dialErr != nil {
		m.current = nil
	}
	m.dialing = false
	m.mu.Unlock()
	close(done)

	if dialErr != nil {
		return nil, dialErr
	}
	startDropMonitor(m, conn, cclient)
	slog.Info("QUIC connection established", "server", m.serverAddr)
	return conn, nil
}

// openControlAndRecord opens the control stream immediately after a successful
// dial, records the live conn and control client under the manager mutex, and
// returns the client. On control-open failure the conn is closed (with 0x03)
// and the mutex fields are left nil. This is the shared post-dial tail called
// by both Establish and get so the control-open logic and mutex bookkeeping are
// never duplicated.
func openControlAndRecord(ctx context.Context, m *connManager, conn transport.Conn) (*control.Client, error) {
	cclient, err := control.Open(ctx, conn, clientVersion, control.OpenOpts{
		KeyCreated: m.keyCreated,
	})
	if err != nil {
		// The agent can reject our pin after our own handshake completes.
		// When that happens, the rejection surfaces on the control-open error
		// or the connection's close cause rather than at Dial. Check both
		// before closing the conn so we don't overwrite the remote cause with
		// our own CloseWithError call, then classify and propagate accordingly.
		if authErr := transport.AuthError(err); authErr != nil {
			err = authErr
		} else if authErr := transport.AuthError(context.Cause(conn.Context())); authErr != nil {
			err = authErr
		}
		_ = conn.CloseWithError(0x03, "control open failed")
		m.mu.Lock()
		m.current = nil
		m.controlClient = nil
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Lock()
	m.current = conn
	m.controlClient = cclient
	m.mu.Unlock()
	return cclient, nil
}

// startDropMonitor launches the goroutine that watches for a connection drop
// and nils out m.current so the next get() triggers a fresh dial. It also
// closes the control client when the connection dies. Exactly one monitor is
// started per successful dial (from Establish or get), so the drop-monitor
// code is never duplicated.
func startDropMonitor(m *connManager, conn transport.Conn, cc *control.Client) {
	go func() {
		<-conn.Context().Done()
		m.mu.Lock()
		if m.current == conn {
			m.current = nil
			m.controlClient = nil
		}
		m.mu.Unlock()
		if cc != nil {
			_ = cc.Close()
		}
		slog.Info("QUIC connection dropped; will re-dial on next request")
	}()
}

// Close closes the current QUIC connection gracefully so the peer receives a
// CONNECTION_CLOSE frame immediately rather than waiting for the idle timeout.
// It is called after the accept loops stop (ctx cancelled, wg done) so no new
// streams can be opened on the connection being closed.
func (m *connManager) Close() {
	m.mu.Lock()
	conn := m.current
	cc := m.controlClient
	m.current = nil
	m.controlClient = nil
	m.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "client shutting down")
	}
	if cc != nil {
		_ = cc.Close()
	}
}

// invalidate marks conn as dead so the next get() will re-dial.
func (m *connManager) invalidate(conn transport.Conn) {
	m.mu.Lock()
	if m.current == conn {
		m.current = nil
	}
	m.mu.Unlock()
}

// dialWithBackoff dials serverAddr, retrying with capped exponential backoff.
// Non-retriable errors (auth failures) return immediately after maxRetries.
func (m *connManager) dialWithBackoff(ctx context.Context) (transport.Conn, error) {
	const maxRetries = 5
	backoff := 200 * time.Millisecond
	const maxBackoff = 30 * time.Second

	for attempt := 0; ; attempt++ {
		conn, err := m.t.Dial(ctx, m.serverAddr)
		if err == nil {
			return conn, nil
		}
		// A pin rejection never self-heals — do not burn retries on it.
		if errors.Is(err, transport.ErrAuthFailed) {
			return nil, err
		}
		if attempt >= maxRetries {
			return nil, fmt.Errorf("dial failed after %d attempts: %w", maxRetries+1, err)
		}
		slog.Warn("dial failed, will retry",
			"attempt", attempt+1,
			"err", err,
			"backoff", backoff,
		)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			backoff = min(backoff*2, maxBackoff)
		}
	}
}
