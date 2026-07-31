package probe_test

// Tests for probe.Ping.
//
// Three concerns are tested here:
//
//  1. Real-QUIC loopback: proves the transport RTT is sampled AFTER the control
//     RPC and that control_rpc_rtt >= min_rtt holds on loopback (where the old
//     code violated the invariant in 5 of 9 probes).
//
//  2. No-measurement path: proves that when MeanDeviation == 0 (no ACK-based
//     RTT sample has been taken) HasRTT is false and the transport RTT fields
//     are not reported as real measurements.
//
//  3. Genuine ~100 ms path not suppressed: proves that a connection whose
//     MeanDeviation is non-zero and whose SmoothedRTT happens to be near
//     100 ms is NOT suppressed as a false placeholder, directly contradicting
//     the naive equality-check approach ("if smoothed_rtt == 100ms → n/a").

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---- helpers -----------------------------------------------------------------

func mustGenIdentity(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("identity.PinForKey: %v", err)
	}
	return key, pin
}

func mustServerTLS(t *testing.T, key ed25519.PrivateKey, authorized []string) *tls.Config {
	t.Helper()
	c, err := identity.ServerTLS(key, authorized)
	if err != nil {
		t.Fatalf("identity.ServerTLS: %v", err)
	}
	return c
}

func mustClientTLS(t *testing.T, key ed25519.PrivateKey, serverPin string) *tls.Config {
	t.Helper()
	c, err := identity.ClientTLS(key, serverPin)
	if err != nil {
		t.Fatalf("identity.ClientTLS: %v", err)
	}
	return c
}

// mustStartServe starts a QUIC agent (tunnel.Serve) on a loopback UDP socket
// and returns the server's address. Cleanup is registered with t.
func mustStartServe(t *testing.T, ctx context.Context, tlsConf *tls.Config, rtr *router.Router) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("server UDP: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	tr, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatalf("server transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen()
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck
	return ln.Addr().String()
}

func mustRouter(t *testing.T, overrides map[string]string) *router.Router {
	t.Helper()
	r, err := router.New(overrides, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	return r
}

// runEchoServer accepts TCP connections and echoes all data back.
func runEchoServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n]) //nolint:errcheck
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}

// ---- Test 1: real-QUIC loopback ----------------------------------------------

// TestPing_RTTSampledAfterRPC is a real-QUIC loopback test. It proves two
// things about the fix:
//
//  1. Re-sampling after the RPC: on loopback at least one ACK must have been
//     processed by the time the RPC returns, so HasRTT must be true (before
//     the fix, sampling at handshake completion could miss this).
//
//  2. The control_rpc_rtt >= min_rtt invariant: RPCInvariantViolation must be
//     nil on loopback. Before the fix, sampling RTT too early caused
//     control_rpc_rtt < min_rtt in 5 of 9 loopback probes.
//
// This test binds to 127.0.0.1:0 (no fixed ports, no privileges).
func TestPing_RTTSampledAfterRPC(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// Minimal echo service so the agent has a route to dial.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()})
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	tr, err := transport.NewQUICTransport(udpConn, clientTLS, nil)
	if err != nil {
		t.Fatalf("NewQUICTransport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	res, err := probe.Ping(ctx, tr, serverAddr)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// The transport RTT must be a real measurement: on loopback the QUIC stack
	// has definitely processed at least one ACK by the time the RPC returns.
	if !res.HasRTT {
		t.Error("HasRTT is false on loopback: RTT was sampled before any ACK arrived")
	}

	// The invariant control_rpc_rtt >= min_rtt must hold when RTT is measured.
	// Before the fix, sampling RTT at handshake completion (before the RPC)
	// caused control_rpc_rtt < min_rtt in more than half of loopback probes.
	if res.RPCInvariantViolation != nil {
		t.Errorf("invariant violation on loopback (was the RTT sampled too early?): %v",
			res.RPCInvariantViolation)
	}

	// Sanity: handshake time must be non-zero.
	if res.HandshakeTime == 0 {
		t.Error("HandshakeTime is zero")
	}

	t.Logf("handshake=%v HasRTT=%v smoothed_rtt=%v min_rtt=%v latest_rtt=%v control_rpc_rtt=%v",
		res.HandshakeTime, res.HasRTT, res.SmoothedRTT, res.MinRTT, res.LatestRTT, res.RPCRoundTrip)
}

// ---- Test 2: no-measurement path --------------------------------------------

// TestPing_NoMeasurement proves that when the connection returns a zeroed
// ConnStats (MeanDeviation == 0), probe.Ping sets HasRTT = false so the caller
// knows not to display the transport RTT fields as real measurements.
//
// The mem transport's Stats() always returns zeroed ConnStats — it has no real
// network layer, so MeanDeviation is always 0 and HasRTT must be false.
//
// Behavioural evidence for the old tree: before the fix, probe.Ping did not
// expose HasRTT at all. A caller had no way to distinguish a genuine 100 ms
// measurement from the seed placeholder; it printed the number regardless. The
// new Result.HasRTT field is the change; its value on the mem path (false)
// proves the detection logic is wired.
func TestPing_NoMeasurement(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (server): %v", err)
	}

	hub := mem.NewHub()
	const srvAddr = "probe-test-server:1"
	srvT := hub.Transport(srvAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("probe-test-client:1", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Minimal echo service for the agent.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	srvCtx, srvCancel := context.WithCancel(ctx)
	t.Cleanup(srvCancel)
	go tunnel.Serve(srvCtx, ln, rtr) //nolint:errcheck

	res, err := probe.Ping(ctx, cliT, srvAddr)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// mem.Stats() returns MeanDeviation == 0, so HasRTT must be false.
	// The RTT fields are the seeded placeholder, not a real measurement.
	if res.HasRTT {
		t.Error("HasRTT should be false when MeanDeviation == 0 (mem transport: no real ACK sampling)")
	}

	// The no-measurement path must still succeed (no error, RPC works).
	if res.RPCErr != nil {
		t.Errorf("unexpected RPCErr on no-measurement path: %v", res.RPCErr)
	}
	if res.RPCRoundTrip == 0 {
		t.Error("RPCRoundTrip should be non-zero even when transport RTT is unmeasured")
	}
}

// ---- Test 3: genuine ~100 ms path not suppressed ----------------------------

// TestPing_Genuine100msNotSuppressed proves that a connection whose
// MeanDeviation is non-zero (i.e. a real ACK sample was taken) reports
// HasRTT = true even when the SmoothedRTT happens to be near 100 ms.
//
// This is the trap in the naive fix: if the detection strategy was
// "if smoothed_rtt == 100ms → n/a" it would silently suppress genuine
// measurements on 100 ms paths (the 5G dataset in the field report).
//
// The statsOverrideTransport wraps a mem transport but overrides Stats() to
// return a ConnStats with SmoothedRTT = 100 ms AND MeanDeviation = 50 ms
// (non-zero). HasRTT must be true because the detection key is MeanDeviation,
// not the RTT value itself.
func TestPing_Genuine100msNotSuppressed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (server): %v", err)
	}

	hub := mem.NewHub()
	const srvAddr = "probe-test-server:2"
	srvT := hub.Transport(srvAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("probe-test-client:2", mem.WithCert(clientLeaf))

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
	go runEchoServer(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	srvCtx, srvCancel := context.WithCancel(ctx)
	t.Cleanup(srvCancel)
	go tunnel.Serve(srvCtx, ln, rtr) //nolint:errcheck

	// Wrap the client transport: Dial succeeds (real mem conn) but Stats()
	// returns SmoothedRTT ≈ 100 ms with non-zero MeanDeviation to simulate a
	// genuine 100 ms path that has been measured.
	const fakeRTT = 100 * time.Millisecond
	const fakeMeanDev = 50 * time.Millisecond // non-zero → HasRTT must be true
	wrappedT := &statsOverrideTransport{
		inner: cliT,
		stats: transport.ConnStats{
			SmoothedRTT:   fakeRTT,
			MinRTT:        fakeRTT,
			LatestRTT:     fakeRTT,
			MeanDeviation: fakeMeanDev,
		},
	}

	res, err := probe.Ping(ctx, wrappedT, srvAddr)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// The critical assertion: a SmoothedRTT near 100 ms must NOT be treated
	// as a placeholder when MeanDeviation is non-zero. HasRTT must be true.
	if !res.HasRTT {
		t.Error("HasRTT is false for a genuine 100 ms path (MeanDeviation != 0): naive equality check broke real measurements")
	}

	if res.SmoothedRTT != fakeRTT {
		t.Errorf("SmoothedRTT = %v, want %v", res.SmoothedRTT, fakeRTT)
	}
}

// ---- statsOverrideTransport -------------------------------------------------

// statsOverrideTransport wraps a transport.Transport and intercepts Dial to
// return a statsOverrideConn — a conn that delegates every operation to the
// underlying connection except Stats(), which returns the provided fixed values.
// This lets tests model specific RTT scenarios without a real network.
type statsOverrideTransport struct {
	inner transport.Transport
	stats transport.ConnStats
}

func (t *statsOverrideTransport) Dial(ctx context.Context, addr string) (transport.Conn, error) {
	c, err := t.inner.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &statsOverrideConn{Conn: c, fixedStats: t.stats}, nil
}

func (t *statsOverrideTransport) Listen() (transport.Listener, error) { return t.inner.Listen() }
func (t *statsOverrideTransport) Close() error                        { return t.inner.Close() }

// statsOverrideConn delegates everything to the embedded Conn except Stats(),
// which returns fixed values supplied at construction. The override allows a
// test to inject any combination of SmoothedRTT and MeanDeviation regardless
// of whether the underlying transport took any real RTT measurement.
type statsOverrideConn struct {
	transport.Conn
	fixedStats transport.ConnStats
}

func (c *statsOverrideConn) Stats() transport.ConnStats { return c.fixedStats }

// PeerCertificates is forwarded so identity checks still work.
func (c *statsOverrideConn) PeerCertificates() []*x509.Certificate {
	return c.Conn.PeerCertificates()
}
