package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// Connect accepts TCP connections on localLn and forwards each one to the
// QUIC agent at serverAddr via t as a single QUIC stream. Each stream is
// prefixed with a protocol-v1 header naming the logical target; the
// client waits for the agent's response before any payload flows.
// A single QUIC connection is shared across all TCP sessions and is
// re-established automatically if it drops (capped exponential backoff).
// Runs until ctx is cancelled or localLn is closed.
func Connect(
	ctx context.Context,
	t transport.Transport,
	serverAddr string,
	target string,
	localLn net.Listener,
) error {
	mgr := &connManager{t: t, serverAddr: serverAddr}
	go func() {
		<-ctx.Done()
		localLn.Close()
	}()
	for {
		tcpConn, err := localLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("local accept: %w", err)
			}
		}
		go forwardTCP(ctx, mgr, tcpConn, target)
	}
}

// forwardTCP opens a QUIC stream to the agent, stamps the protocol header,
// waits for a success response, and then proxies data between tcpConn and the
// stream. It retries the stream open once if the first attempt fails (handles
// the race where the QUIC connection dropped between get and use).
func forwardTCP(ctx context.Context, mgr *connManager, tcpConn net.Conn, target string) {
	defer tcpConn.Close()

	start := time.Now()
	slog.Info("session opened", "local", tcpConn.RemoteAddr(), "target", target)
	defer func() {
		slog.Info("session closed",
			"local", tcpConn.RemoteAddr(),
			"duration", time.Since(start).Round(time.Millisecond),
		)
	}()

	conn, err := mgr.get(ctx)
	if err != nil {
		slog.Warn("get QUIC conn", "err", err)
		return
	}

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		// Connection may have died since we got it; invalidate and retry once.
		mgr.invalidate(conn)
		conn, err = mgr.get(ctx)
		if err != nil {
			slog.Warn("get QUIC conn (retry)", "err", err)
			return
		}
		stream, err = conn.OpenStream(ctx)
		if err != nil {
			slog.Warn("open QUIC stream", "err", err)
			return
		}
	}

	// Name a logical target; never an ip:port.
	if err := proto.WriteHeader(stream, proto.Header{Kind: proto.KindTCP, Target: target}); err != nil {
		slog.Warn("write header", "err", err, "target", target)
		stream.Reset(proto.StreamResetCode)
		resetConn(tcpConn)
		return
	}

	// Wait for the response (10s deadline) before sending any payload.
	resp, err := awaitResponse(ctx, stream, proto.ResponseDeadline)
	if err != nil {
		slog.Warn("await response", "err", err, "target", target)
		resetConn(tcpConn) // stream already reset by awaitResponse
		return
	}
	if resp.Status != proto.StatusOK {
		// Surface the agent's message verbatim.
		slog.Warn("agent refused stream",
			"target", target,
			"status", uint(resp.Status),
			"status_name", resp.Status.String(),
			"msg", resp.Msg,
		)
		stream.Reset(proto.StreamResetCode)
		resetConn(tcpConn)
		return
	}

	// pipe closes tcpConn (a) and stream (b) when done.
	pipe(tcpConn, stream)
}

// awaitResponse reads the agent's response frame, enforcing the response
// deadline. On timeout, context cancellation, or a read error it resets the
// stream (which also unblocks the read goroutine) and returns an error.
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

// connManager maintains a single persistent QUIC connection to serverAddr.
// Concurrent callers share one in-flight dial via a single-flight mechanism.
type connManager struct {
	mu         sync.Mutex
	current    transport.Conn
	dialErr    error
	dialing    bool
	dialDone   chan struct{}
	t          transport.Transport
	serverAddr string
}

// get returns the current QUIC connection or dials a new one.  If a dial is
// already in progress, callers block on the shared result.
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

	conn, err := m.dialWithBackoff(ctx)

	m.mu.Lock()
	m.current = conn
	m.dialErr = err
	m.dialing = false
	m.mu.Unlock()
	close(done)

	if err != nil {
		return nil, err
	}
	slog.Info("QUIC connection established", "server", m.serverAddr)

	// Monitor for connection drop and nil out m.current so the next caller
	// triggers a fresh dial.
	go func() {
		<-conn.Context().Done()
		m.mu.Lock()
		if m.current == conn {
			m.current = nil
		}
		m.mu.Unlock()
		slog.Info("QUIC connection dropped; will re-dial on next request")
	}()

	return conn, nil
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
