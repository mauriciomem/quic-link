package daemon_test

// reconnect_soak_test.go — Port 2: real-QUIC reconnect soak. Replaces
// internal/tunnel/integration_test.go's TestReconnectSoak (deleted along with
// tunnel.Connect, its only caller). Exercises the survivor, dialEntry, via
// daemon.NewRealPool: multiple forced drops, a byte-exact echo re-verified
// through a real DoAttach splice after each reconnect, and a goroutine-count
// check across the exact cycles under test (daemon's TestMain already runs
// goleak.VerifyTestMain at the whole-package level; this adds a live,
// in-test bound on growth across repeated reconnects specifically).
//
// Real QUIC (not mem) is used deliberately — this is one of the few tests
// that legitimately needs it, per the reconnect soak's original intent of
// exercising real transport-level drop/re-handshake behavior.

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestPool_ReconnectSoak_RealQUIC replaces TestReconnectSoak. It drives
// dialEntry through five forced drop/reconnect cycles over real QUIC,
// re-verifying a byte-exact echo through a live DoAttach splice after each
// reconnect and asserting the connection handed back each time is distinct
// from the one before it, then checks that goroutine count has not grown
// beyond a small allowance across the whole soak.
func TestPool_ReconnectSoak_RealQUIC(t *testing.T) {
	t.Parallel()
	const cycles = 5
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	serverKey, serverPin := genPoolIdentity(t)
	clientKey, clientPin := genPoolIdentity(t)
	serverTLS, err := identity.ServerTLS(serverKey, []string{clientPin})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	clientTLS, err := identity.ClientTLS(clientKey, serverPin)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runDaemonEchoServer(echoLn)

	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("server UDP: %v", err)
	}
	t.Cleanup(func() { serverUDP.Close() })
	serverTr, err := transport.NewQUICTransport(serverUDP, serverTLS, nil)
	if err != nil {
		t.Fatalf("server transport: %v", err)
	}
	t.Cleanup(func() { serverTr.Close() })
	innerLn, err := serverTr.Listen()
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { innerLn.Close() })

	serverConns := make(chan transport.Conn, cycles+1)
	trackedLn := &chanTrackingListener{inner: innerLn, conns: serverConns}

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, trackedLn, rtr) }()

	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { clientUDP.Close() })
	clientTr, err := transport.NewQUICTransport(clientUDP, clientTLS, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { clientTr.Close() })

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"soak-server": {Addr: innerLn.Addr().String()},
	}

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return clientTr, nil },
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	waitForPoolState(t, pool, "soak-server", "connected", 10*time.Second)

	// Let the initial dial's goroutines (probe, drop-wait) settle before
	// taking the baseline.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := range cycles {
		var serverConn transport.Conn
		select {
		case serverConn = <-serverConns:
		case <-time.After(5 * time.Second):
			t.Fatalf("cycle %d: timed out waiting for server-side connection", i)
		}

		// conn is whatever is currently live: cycle 0's initial eager dial, or
		// the previous cycle's post-redial conn — no new drop has happened
		// yet for this cycle.
		conn, err := pool.Get(ctx, "soak-server")
		if err != nil {
			t.Fatalf("cycle %d: Get before drop: %v", i, err)
		}
		assertUsable(t, ctx, conn, fmt.Sprintf("cycle%d-pre", i))

		// Force-close the server side of THIS cycle's connection.
		if err := serverConn.CloseWithError(0, "soak-test drop"); err != nil {
			t.Logf("cycle %d: CloseWithError: %v", i, err)
		}

		newConn := waitForDistinctConn(t, ctx, pool, "soak-server", conn, 10*time.Second)
		assertUsable(t, ctx, newConn, fmt.Sprintf("cycle%d-post", i))
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Reject monotonic goroutine growth; allow a small constant for test
	// infrastructure (echo-server per-conn goroutines, splice teardown) that
	// may not have fully unwound yet.
	const allowance = 15
	if after > baseline+allowance {
		t.Errorf("goroutine count grew across %d reconnect cycles: baseline=%d after=%d (allowance=%d)",
			cycles, baseline, after, allowance)
	}
	t.Logf("goroutine count: baseline=%d after-soak=%d (cycles=%d)", baseline, after, cycles)
}
