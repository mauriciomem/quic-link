package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Connect accepts TCP connections on localLn and forwards each one to the
// QUIC server at serverAddr via t as a single QUIC stream.
// A single QUIC connection is shared across all TCP sessions and is
// re-established automatically if it drops (capped exponential backoff).
// Runs until ctx is cancelled or localLn is closed.
func Connect(
	ctx context.Context,
	t transport.Transport,
	serverAddr string,
	localLn net.Listener,
) error {
	mgr := &connManager{t: t, serverAddr: serverAddr}
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
		go forwardTCP(ctx, mgr, tcpConn)
	}
}

// forwardTCP opens a QUIC stream to the server and proxies data between
// tcpConn and the stream.  It retries once if the first stream open fails
// (handles the race where the QUIC connection dropped between get and use).
func forwardTCP(ctx context.Context, mgr *connManager, tcpConn net.Conn) {
	defer tcpConn.Close()

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
	// pipe closes tcpConn (a) and stream (b) when done.
	pipe(tcpConn, stream)
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
