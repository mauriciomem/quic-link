package daemon_test

// A session that is up should be able to say how it is reaching the far end,
// and a session that is not up should say nothing rather than guess.
//
// The hard case, and the reason these tests use real sockets rather than the
// in-memory transport, is a session the far end opened. That socket accepts
// both address families, so it reports only that it accepts both; if the family
// were read from the socket, every such session would be reported as IPv6 no
// matter how the peer actually arrived. Only the connection can answer, and
// only a real one has an address to answer with.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// requireIPv6Socket skips when the machine has no IPv6 at all, so the result
// says "not tested here" instead of reporting a failure that belongs to the
// machine rather than the code.
func requireIPv6Socket(t *testing.T) {
	t.Helper()
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("this machine cannot open an IPv6 socket, so there is nothing to check: %v", err)
	}
	c.Close()
}

// waitForPath polls until a server reports a state and a path, and fails with
// what it last saw rather than waiting forever. A test that can only run out of
// time reports a stalled run instead of the thing it was written to detect.
func waitForPath(t *testing.T, pool daemon.SessionPool, name string, budget time.Duration) (string, string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var lastState, lastPath string
	for time.Now().Before(deadline) {
		for _, st := range pool.State() {
			if st.Name != name {
				continue
			}
			lastState, lastPath = st.State, st.Path
			if st.State == "connected" {
				return st.State, st.Path
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server %q never connected within %s; last seen state %q path %q",
		name, budget, lastState, lastPath)
	return "", ""
}

// startRealAgent brings up an agent on a real socket and returns the address it
// took. The network string decides which families it can be reached on.
func startRealAgent(t *testing.T, ctx context.Context, network string, ip net.IP, clientPin string) (string, string) {
	t.Helper()

	agentKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	agentPin, err := identity.PinForKey(agentKey)
	if err != nil {
		t.Fatalf("agent pin: %v", err)
	}
	tlsConf, err := identity.AgentListenTLS(agentKey, []string{clientPin})
	if err != nil {
		t.Fatalf("agent TLS: %v", err)
	}

	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatalf("agent socket (%s): %v", network, err)
	}
	t.Cleanup(func() { conn.Close() })

	tr, err := transport.NewQUICListenTransport(conn, tlsConf, nil)
	if err != nil {
		t.Fatalf("agent transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen()
	if err != nil {
		t.Fatalf("agent listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	return ln.Addr().String(), agentPin
}

// dialPoolTo builds a daemon pool that connects out to one address on a real
// socket, in the family that address needs.
func dialPoolTo(t *testing.T, ctx context.Context, addr, agentPin string, clientKey ed25519.PrivateKey) daemon.SessionPool {
	t.Helper()

	// The same key whose pin the agent was told to authorise. Generating a
	// fresh one here would be rejected, and the session would report a
	// permanent authentication failure rather than a path.
	tlsConf, err := identity.ClientDialTLS(clientKey, agentPin)
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"peer": {Addr: addr}}

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			network := "udp4"
			ip := net.IPv4zero
			if host, _, err := net.SplitHostPort(addr); err == nil {
				if parsed := net.ParseIP(host); parsed != nil && parsed.To4() == nil {
					network, ip = "udp6", net.IPv6zero
				}
			}
			conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			if err != nil {
				return nil, err
			}
			return transport.NewQUICTransport(conn, tlsConf, nil)
		},
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestASessionOverIPv4SaysSo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	clientKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientPin, err := identity.PinForKey(clientKey)
	if err != nil {
		t.Fatalf("client pin: %v", err)
	}

	addr, agentPin := startRealAgent(t, ctx, "udp4", net.IPv4(127, 0, 0, 1), clientPin)
	pool := dialPoolTo(t, ctx, addr, agentPin, clientKey)

	_, path := waitForPath(t, pool, "peer", 15*time.Second)
	if path != "ipv4-direct" {
		t.Errorf("a session over IPv4 reports path %q, want %q", path, "ipv4-direct")
	}
}

func TestASessionOverIPv6SaysSo(t *testing.T) {
	requireIPv6Socket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	clientKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientPin, err := identity.PinForKey(clientKey)
	if err != nil {
		t.Fatalf("client pin: %v", err)
	}

	addr, agentPin := startRealAgent(t, ctx, "udp6", net.IPv6loopback, clientPin)
	pool := dialPoolTo(t, ctx, addr, agentPin, clientKey)

	_, path := waitForPath(t, pool, "peer", 15*time.Second)
	if path != "ipv6-direct" {
		t.Errorf("a session over IPv6 reports path %q, want %q", path, "ipv6-direct")
	}
}

// TestADisabledServerNamesNoPath is required rather than optional: the goldens
// are built from hand-written states, so they cannot catch a real disabled entry
// reporting a path. Only this test can.
func TestADisabledServerNamesNoPath(t *testing.T) {
	disabled := false
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"off": {Addr: "192.0.2.10:7443", Enabled: &disabled},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			t.Fatal("a disabled server must not build a transport")
			return nil, nil
		},
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	for _, st := range pool.State() {
		if st.Path != "" {
			t.Errorf("a server that is switched off reports path %q; nothing was ever attempted, "+
				"so there is no route to name", st.Path)
		}
	}

	noSidecar := func(string) (time.Time, bool, error) { return time.Time{}, false, nil }
	raw, err := json.Marshal(daemon.BuildSnapshot(pool.State(), daemon.WallClock{}, "", 0, noSidecar))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "path") {
		t.Errorf("the document names a path for a server that was never attempted: %s", raw)
	}
}

// TestAPeerArrivingOverIPv4IsNotReportedAsIPv6 is the test the whole design
// turns on, and the only one that can tell the right design from the wrong one.
//
// The daemon waits on a socket that accepts both address families, so the socket
// itself can only report that it accepts both — which reads as IPv6. An agent
// then arrives over IPv4. If the reported path came from the socket, this would
// say IPv6 and be wrong; it has to come from the connection, which carries the
// address the peer actually used.
//
// Its IPv6 counterpart below passes under either design and is therefore a
// control, not a discriminator. Do not drop this one for time.
func TestAPeerArrivingOverIPv4IsNotReportedAsIPv6(t *testing.T) {
	requireIPv6Socket(t)
	assertArrivingPeerPath(t, "udp4", net.IPv4(127, 0, 0, 1), "127.0.0.1", "ipv4-direct")
}

func TestAPeerArrivingOverIPv6IsReportedAsIPv6(t *testing.T) {
	requireIPv6Socket(t)
	assertArrivingPeerPath(t, "udp6", net.IPv6loopback, "::1", "ipv6-direct")
}

// assertArrivingPeerPath stands up a daemon waiting on a socket that accepts
// both families, has an agent connect in over one of them, and checks the
// reported path names the family the agent actually used.
func assertArrivingPeerPath(t *testing.T, agentNetwork string, agentIP net.IP, dialHost, wantPath string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	daemonKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("daemon key: %v", err)
	}
	daemonPin, err := identity.PinForKey(daemonKey)
	if err != nil {
		t.Fatalf("daemon pin: %v", err)
	}
	agentKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	agentPin, err := identity.PinForKey(agentKey)
	if err != nil {
		t.Fatalf("agent pin: %v", err)
	}

	// The socket that cannot say which family a peer used. Binding "udp" with
	// no address is what a configured listen port produces, and is the whole
	// reason this test exists.
	waitConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("waiting socket: %v", err)
	}
	t.Cleanup(func() { waitConn.Close() })
	waitPort := waitConn.LocalAddr().(*net.UDPAddr).Port
	if waitConn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		t.Fatalf("the waiting socket is IPv4 only (%s); this test needs one that accepts both "+
			"families, or it is not testing anything", waitConn.LocalAddr())
	}

	daemonTLS, err := identity.ClientListenTLS(daemonKey, agentPin)
	if err != nil {
		t.Fatalf("daemon TLS: %v", err)
	}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"inbound": {Listen: ":0", Pin: agentPin}}

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return transport.NewQUICListenTransport(waitConn, daemonTLS, nil)
		},
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// Nothing has arrived, so there is no route to name.
	for _, st := range pool.State() {
		if st.Path != "" {
			t.Errorf("a server still waiting for its peer reports path %q; nothing has arrived",
				st.Path)
		}
	}

	// The agent connects in over one family only.
	agentTLS, err := identity.AgentDialTLS(agentKey, []string{daemonPin})
	if err != nil {
		t.Fatalf("agent TLS: %v", err)
	}
	agentConn, err := net.ListenUDP(agentNetwork, &net.UDPAddr{IP: agentIP})
	if err != nil {
		t.Fatalf("agent socket (%s): %v", agentNetwork, err)
	}
	t.Cleanup(func() { agentConn.Close() })

	agentTr, err := transport.NewQUICTransport(agentConn, agentTLS, nil)
	if err != nil {
		t.Fatalf("agent transport: %v", err)
	}
	t.Cleanup(func() { agentTr.Close() })

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	target := net.JoinHostPort(dialHost, strconv.Itoa(waitPort))
	go tunnel.DialAndServe(ctx, agentTr, target, rtr, ceilingPolicy(), daemon.WallClock{}) //nolint:errcheck

	_, path := waitForPath(t, pool, "inbound", 15*time.Second)
	if path != wantPath {
		t.Errorf("a peer that arrived over %s is reported as %q, want %q; the family is being read "+
			"from the waiting socket, which accepts both and cannot say", agentNetwork, path, wantPath)
	}
}
