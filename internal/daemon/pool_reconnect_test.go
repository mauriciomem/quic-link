package daemon_test

// pool_reconnect_test.go covers:
//
//  Port 1 — drop → successful redial → distinct new conn. Replaces
//  internal/tunnel/connect_mem_test.go's TestConnManager_Get_ReDialsAfterDrop
//  (deleted along with connManager). No daemon-side test previously confirmed
//  this property directly: TestSessionLost_* and TestLivenessProbe_* (in
//  pool_liveness_test.go) only prove DETECTION — that state leaves
//  "connected" — they never bring the agent back and confirm pool.Get()
//  hands back a new, DISTINCT, usable connection afterward.
//
// This file also holds test helpers shared with reconnect_soak_test.go
// (Port 2, real QUIC) and pool_close_test.go (Port 4): waitForPoolState,
// waitForDistinctConn, assertUsable, runDaemonEchoServer, and
// chanTrackingListener.

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- shared helpers -----------------------------------------------------

// waitForPoolState polls (bounded, not a fixed sleep) until the named entry
// reports want, or fails the test after budget elapses.
func waitForPoolState(t *testing.T, pool daemon.SessionPool, server, want string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		state, err := pool.EntryState(server)
		if err != nil {
			t.Fatalf("EntryState(%q): %v", server, err)
		}
		if state == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, _ := pool.EntryState(server)
	t.Fatalf("pool did not reach state %q for %q within %s (last seen: %q)", want, server, budget, got)
}

// waitForDistinctConn polls pool.Get(server) (bounded, not a fixed sleep)
// until it returns a conn different from avoid, or fails the test.
//
// Polling the public Get() API — rather than an internal state string — has
// no blind spot for a redial that completes faster than an external poll
// interval could reliably observe the transient "connecting" state: with
// zero-delay backoff over mem the whole drop+redial cycle can complete in
// well under a millisecond. Every Get() call here either blocks (dial in
// flight), returns the stale conn (redial not yet started — loop again), or
// returns the new one (done); there is no window in which the property under
// test could be missed.
func waitForDistinctConn(t *testing.T, ctx context.Context, pool daemon.SessionPool, server string, avoid daemon.Conn, budget time.Duration) daemon.Conn {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		c, err := pool.Get(ctx, server)
		if err != nil {
			t.Fatalf("Get(%q): %v", server, err)
		}
		if c != nil && c != avoid {
			return c
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pool did not hand back a conn distinct from the previous one for %q within %s", server, budget)
	return nil
}

// assertUsable proves conn is not just non-nil but genuinely carries traffic:
// it drives a real DoAttach splice over conn's "ssh" route (the same path
// production attach uses) and checks a byte-exact echo.
func assertUsable(t *testing.T, ctx context.Context, conn daemon.Conn, label string) {
	t.Helper()

	localA, localB := net.Pipe()
	defer localA.Close()

	payload := []byte("usable-check-" + label)
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- tunnel.DoAttach(ctx, conn, localA, "ssh", "reconnect-test-"+label, nil)
	}()

	if _, err := localB.Write(payload); err != nil {
		t.Fatalf("%s: write: %v", label, err)
	}
	got := make([]byte, len(payload))
	localB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(localB, got); err != nil {
		t.Fatalf("%s: ReadFull: %v", label, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("%s: echo mismatch: got %q want %q", label, got, payload)
	}

	localB.Close()
	select {
	case <-attachDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: DoAttach did not return after local close", label)
	}
}

// runDaemonEchoServer accepts TCP connections and echoes all data back. It
// backs the "ssh" route used by assertUsable.
func runDaemonEchoServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c) //nolint:errcheck
		}(c)
	}
}

// chanTrackingListener wraps a transport.Listener and forwards each accepted
// Conn to a channel before returning it to the caller. This lets a test
// observe the PEER (agent) side of a connection the client-side pool is
// driving — needed to prove a close signal actually reaches the other side,
// not just that the client-local reference was niled out.
type chanTrackingListener struct {
	inner transport.Listener
	conns chan transport.Conn
}

func (l *chanTrackingListener) Accept(ctx context.Context) (transport.Conn, error) {
	conn, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case l.conns <- conn:
	default:
	}
	return conn, nil
}

func (l *chanTrackingListener) Addr() net.Addr { return l.inner.Addr() }
func (l *chanTrackingListener) Close() error   { return l.inner.Close() }

// ---- Port 1 --------------------------------------------------------------

// TestPool_DropThenRedial_ReturnsDistinctUsableConn replaces
// TestConnManager_Get_ReDialsAfterDrop. It proves the property that test
// guarded, now against dialEntry via the exported pool constructor: after the
// live connection drops, the pool re-dials automatically against the SAME
// agent listener and hands back a DIFFERENT connection that actually carries
// traffic — not just a non-nil pointer.
func TestPool_DropThenRedial_ReturnsDistinctUsableConn(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub := mem.NewHub()
	srvLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	srvT := hub.Transport("redial-agent:1", mem.WithCert(srvLeaf))
	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runDaemonEchoServer(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	// tunnel.Serve keeps accepting on ln for the life of the test, so a
	// dropped session can be re-dialed against the SAME listener — this is
	// what makes the redial "successful" rather than merely attempted.
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, ln, rtr) }()

	cliT := hub.Transport("redial-client:1", mem.WithCert(srvLeaf))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"redial-server": {Addr: "redial-agent:1"},
	}

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return cliT, nil },
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	waitForPoolState(t, pool, "redial-server", "connected", 5*time.Second)

	conn1, err := pool.Get(ctx, "redial-server")
	if err != nil {
		t.Fatalf("Get (first): %v", err)
	}
	if conn1 == nil {
		t.Fatal("Get (first): nil conn with no error")
	}
	assertUsable(t, ctx, conn1, "conn1")

	// Force the drop deterministically: close the live connection's context.
	// This delivers the same signal a natural QUIC drop sends to runLoop's
	// <-conn.Context().Done() — no timing is used to CAUSE the drop, only
	// bounded polling to OBSERVE the resulting (bounded) recovery below.
	if err := conn1.CloseWithError(0, "test-forced drop"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	conn2 := waitForDistinctConn(t, ctx, pool, "redial-server", conn1, 5*time.Second)
	assertUsable(t, ctx, conn2, "conn2")
}
