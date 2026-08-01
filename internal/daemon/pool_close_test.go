package daemon_test

// pool_close_test.go — Port 4: graceful close (client). Replaces
// internal/tunnel/graceful_close_test.go's TestGracefulClose_Client (deleted
// along with connManager; TestGracefulClose_Agent was deleted outright as a
// duplicate — both tests' bodies exercised the identical "does the peer's
// Context fire promptly after CloseWithError" assertion despite their
// differing doc comments).
//
// Existing daemon shutdown tests (splice_shutdown_test.go, shutdown_test.go)
// use a fakePool stub and never exercise a REAL transport.Conn's
// CloseWithError → PEER Context() propagation through pool.Close() — that
// was genuinely unguarded. internal/transport/mem's documented harness
// feature is exactly this: Context close-cause propagation on
// CloseWithError, which is why mem (not a fake) is used here.

import (
	"context"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestPool_Close_PeerContextFiresPromptly verifies that pool.Close() causes
// the PEER side's conn.Context() to fire promptly — not on the QUIC idle
// timeout. dialEntry.Close calls conn.CloseWithError on the live connection;
// this test proves that signal actually reaches the OTHER side of a real Conn
// implementation, not just that the client-local reference was niled out.
func TestPool_Close_PeerContextFiresPromptly(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hub := mem.NewHub()
	srvLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	srvT := hub.Transport("close-agent:1", mem.WithCert(srvLeaf))
	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Track the agent-accepted (peer-side) conn so the test can observe ITS
	// Context — not the client-side conn the pool hands back from Get.
	peerConns := make(chan transport.Conn, 1)
	trackedLn := &chanTrackingListener{inner: ln, conns: peerConns}

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, trackedLn, nil) }()

	cliT := hub.Transport("close-client:1", mem.WithCert(srvLeaf))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"close-server": {Addr: "close-agent:1"},
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

	waitForPoolState(t, pool, "close-server", "connected", 5*time.Second)

	var peerConn transport.Conn
	select {
	case peerConn = <-peerConns:
	case <-time.After(2 * time.Second):
		t.Fatal("agent never accepted a connection")
	}

	select {
	case <-peerConn.Context().Done():
		t.Fatal("peer conn.Context() fired before pool.Close() was ever called")
	default:
	}

	closeStart := time.Now()
	pool.Close()

	const promptBudget = 500 * time.Millisecond
	select {
	case <-peerConn.Context().Done():
		elapsed := time.Since(closeStart)
		if elapsed > promptBudget {
			t.Errorf("peer conn.Context() fired after %s (budget %s) — too slow to be "+
				"a graceful CloseWithError propagation", elapsed.Round(time.Millisecond), promptBudget)
		}
		t.Logf("peer conn.Context() fired %s after pool.Close()", elapsed.Round(time.Millisecond))
	case <-time.After(promptBudget):
		t.Fatalf("peer conn.Context() did not fire within %s after pool.Close() — "+
			"CloseWithError did not propagate to the peer side (mem's documented Context "+
			"close-cause propagation is the property under test)", promptBudget)
	}
}
