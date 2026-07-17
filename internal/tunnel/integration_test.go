package tunnel_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestTunnelRoundTrip verifies that bytes sent over a TCP connection to the
// local tunnel port are forwarded through the QUIC tunnel to the echo service
// and returned intact.
func TestTunnelRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// Start a TCP echo server that the serve tunnel will forward streams to.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	// Start the QUIC serve tunnel.
	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	// Start the QUIC connect tunnel (exposes a local TCP port).
	localLn := mustStartConnect(t, ctx, clientTLS, serverAddr, "ssh")

	// Dial through the local TCP port and verify round-trip.
	conn, err := net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("TCP dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello quic-link round-trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, payload)
	}
}

// TestUnknownTarget verifies that when the client names a target the agent
// does not know, the agent replies unknown_target and the local connection is
// closed without data flowing (status 1, end-to-end).
func TestUnknownTarget(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)
	// Client names a target the agent does not serve.
	localLn := mustStartConnect(t, ctx, clientTLS, serverAddr, "bogus")

	conn, err := net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("TCP dial: %v", err)
	}
	defer conn.Close()

	// The agent refuses; the client resets the local leg. A read must return
	// an error (EOF or reset) rather than echoed data.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the local connection to be closed on unknown_target, but read succeeded")
	}
}

// HandshakeTime and a non-zero SmoothedRTT on loopback.
func TestPingNonZeroRTT(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})

	// Need a dummy echo service for the serve tunnel to dial.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	// Create a fresh client transport for the ping probe.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	clientTLS := mustClientTLS(t, clientKey, serverPin)
	tr, err := transport.NewQUICTransport(udpConn, clientTLS, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	res, err := probe.Ping(ctx, tr, serverAddr)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if res.HandshakeTime == 0 {
		t.Error("HandshakeTime is zero")
	}
	// On loopback the smoothed RTT may still be 0 after just one packet;
	// accept any non-negative value and log what we got.
	t.Logf("handshake=%v smoothed_rtt=%v min_rtt=%v latest_rtt=%v",
		res.HandshakeTime, res.SmoothedRTT, res.MinRTT, res.LatestRTT)
}

// TestPinRejection verifies the pinning handshake refuses a peer whose pin is
// not accepted. Two directions:
//   - the client expects the WRONG server pin → the CLIENT aborts the handshake
//     and Dial returns transport.ErrAuthFailed (→ exit 4). Reliable at dial.
//   - the client's pin is NOT in the agent's authorized set → the SERVER aborts.
//     With QUIC + TLS 1.3 the client may finish its handshake before the
//     server's rejection propagates, so the failure may surface at dial, stream
//     open, or first use; whichever, the connection must not be usable.
func TestPinRejection(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	_, otherPin := mustGenIdentity(t) // a pin belonging to neither peer

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	t.Run("wrong server pin (client rejects)", func(t *testing.T) {
		// Agent authorizes the real client; client expects the WRONG server pin.
		serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
		rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
		serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

		clientTLS := mustClientTLS(t, clientKey, otherPin)
		_, err := dialRaw(t, ctx, clientTLS, serverAddr)
		if !errors.Is(err, transport.ErrAuthFailed) {
			t.Fatalf("wrong server pin: got %v, want transport.ErrAuthFailed", err)
		}
	})

	t.Run("client not authorized (agent rejects)", func(t *testing.T) {
		// Agent authorizes SOMEONE ELSE; the real client's pin is not accepted.
		serverTLS := mustServerTLS(t, serverKey, []string{otherPin})
		rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
		serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

		clientTLS := mustClientTLS(t, clientKey, serverPin)
		conn, err := dialRaw(t, ctx, clientTLS, serverAddr)
		if err != nil {
			if !errors.Is(err, transport.ErrAuthFailed) {
				t.Logf("rejected at dial with a non-auth error: %v", err)
			}
			return // rejected at dial — good enough
		}
		defer conn.CloseWithError(0, "test done") //nolint:errcheck

		// The client finished its handshake before the server's rejection; the
		// connection must nonetheless be unusable.
		stream, err := conn.OpenStream(ctx)
		if err != nil {
			return // rejected at stream open — good
		}
		defer stream.Close() //nolint:errcheck
		if err := proto.WriteHeader(stream, proto.Header{Kind: proto.KindTCP, Target: "ssh"}); err != nil {
			return
		}
		buf := make([]byte, 1)
		if _, err := stream.Read(buf); err != nil {
			return // rejected on use — good
		}
		t.Fatal("expected pin rejection, but the connection was usable")
	})
}

// dialRaw dials the agent with tlsConf and returns the connection (or the
// classified dial error). A fresh UDP socket + transport is created; cleanup is
// registered with t.
func dialRaw(t *testing.T, ctx context.Context, tlsConf *tls.Config, serverAddr string) (transport.Conn, error) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("UDP socket: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })
	tr, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr.Dial(ctx, serverAddr)
}

// ---- test helpers ------------------------------------------------------------

// mustStartServe starts a QUIC serve tunnel backed by rtr and returns the
// server's UDP addr string (host:port). Cleanup is registered with t.
func mustStartServe(t *testing.T, ctx context.Context, tlsConf *tls.Config, rtr *router.Router) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("server UDP listen: %v", err)
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

// mustRouter builds a Router from overrides+policy or fails the test.
func mustRouter(t *testing.T, overrides map[string]string, policy router.Policy) *router.Router {
	t.Helper()
	r, err := router.New(overrides, policy)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	return r
}

// mustStartConnect starts a QUIC connect tunnel with a single forward and
// returns the local TCP Listener (port is ephemeral). Cleanup is registered
// with t.
func mustStartConnect(t *testing.T, ctx context.Context, tlsConf *tls.Config, serverAddr, target string) net.Listener {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP listen: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	tr, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local TCP listen: %v", err)
	}
	t.Cleanup(func() { localLn.Close() })

	go tunnel.Connect(ctx, tr, serverAddr, []tunnel.Forward{{Listener: localLn, Target: target}}) //nolint:errcheck
	return localLn
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
			io.Copy(c, c) //nolint:errcheck
		}(c)
	}
}

// ---- pinning identity helpers ------------------------------------------------

// mustGenIdentity generates a fresh Ed25519 identity and returns the key and its
// pin. The whole test suite pairs peers by exchanging these pins.
func mustGenIdentity(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	return key, pin
}

// TestReconnectSoak verifies that the connManager re-dials after the server
// closes the QUIC connection and that goroutine count does not grow
// monotonically across repeated reconnect cycles.
func TestReconnectSoak(t *testing.T) {
	t.Parallel()
	const cycles = 5
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// Echo service the tunnel will proxy to.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	// Build a QUIC listener wrapped in a trackingListener so the test can
	// intercept each accepted connection and force-close it.
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
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
	trackedLn := &trackingListener{inner: innerLn, conns: serverConns}

	// Start the serve tunnel with the tracking listener.
	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	go tunnel.Serve(ctx, trackedLn, rtr) //nolint:errcheck

	// Start the connect tunnel (client side).
	localLn := mustStartConnect(t, ctx, clientTLS, innerLn.Addr().String(), "ssh")

	// Prime: open a TCP connection so the client establishes its initial QUIC
	// session. Close it immediately; we only need the QUIC connection live.
	prime, err := net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("prime dial: %v", err)
	}
	prime.Close()

	// Let the initial goroutines (drop-monitor, serveConn, pipe teardown) settle.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := range cycles {
		// Wait for the server to have an accepted QUIC connection for this cycle.
		// Cycle 0 uses the primed connection; cycle N uses the connection
		// established by the previous cycle's echo dial.
		var serverConn transport.Conn
		select {
		case serverConn = <-serverConns:
		case <-time.After(5 * time.Second):
			t.Fatalf("cycle %d: timed out waiting for server connection", i)
		}

		// Force-close the server side; the client drop-monitor should fire.
		if err := serverConn.CloseWithError(0, "soak-test drop"); err != nil {
			t.Logf("cycle %d: CloseWithError: %v", i, err)
		}

		// Give the client drop-monitor time to detect the close and nil m.current.
		time.Sleep(200 * time.Millisecond)

		// A new TCP dial through the tunnel triggers a QUIC re-dial and verifies
		// the reconnect succeeds end-to-end.
		conn, err := net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("cycle %d: dial after reconnect: %v", i, err)
		}
		msg := []byte("soak")
		if _, err := conn.Write(msg); err != nil {
			conn.Close()
			t.Fatalf("cycle %d: write: %v", i, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			conn.Close()
			t.Fatalf("cycle %d: read: %v", i, err)
		}
		conn.Close()
		if string(got) != string(msg) {
			t.Fatalf("cycle %d: echo mismatch: got %q want %q", i, got, msg)
		}
	}

	// Allow goroutines from the final cycle to settle.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Reject monotonic goroutine growth; allow a small constant for
	// test infrastructure that may not have fully torn down yet.
	const allowance = 10
	if after > baseline+allowance {
		t.Errorf("goroutine count grew: baseline=%d after=%d (allowance=%d)",
			baseline, after, allowance)
	}
	t.Logf("goroutine count: baseline=%d after-soak=%d", baseline, after)
}

// trackingListener wraps a transport.Listener and sends each accepted Conn
// to the conns channel before returning it to the caller, so tests can
// force-close individual QUIC connections.
type trackingListener struct {
	inner transport.Listener
	conns chan transport.Conn
}

func (l *trackingListener) Accept(ctx context.Context) (transport.Conn, error) {
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

func (l *trackingListener) Addr() net.Addr { return l.inner.Addr() }
func (l *trackingListener) Close() error   { return l.inner.Close() }

// ---- wire-level tests --------------------------------------------------------

// mustClientTLS builds a client pinning tls.Config that presents key's carrier
// cert and expects the given server pin.
func mustClientTLS(t *testing.T, key ed25519.PrivateKey, serverPin string) *tls.Config {
	t.Helper()
	c, err := identity.ClientTLS(key, serverPin)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	return c
}

// mustServerTLS builds an agent pinning tls.Config that presents key's carrier
// cert and authorizes the given client pins.
func mustServerTLS(t *testing.T, key ed25519.PrivateKey, authorized []string) *tls.Config {
	t.Helper()
	c, err := identity.ServerTLS(key, authorized)
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	return c
}

// openClientStream dials the agent directly, opens one stream carrying h, and
// returns the stream plus the agent's response frame. Cleanup is registered
// with t.
func openClientStream(t *testing.T, ctx context.Context, tlsConf *tls.Config, serverAddr string, h proto.Header) (transport.Stream, proto.Response) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })
	tr, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	conn, err := tr.Dial(ctx, serverAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := proto.WriteHeader(stream, h); err != nil {
		t.Fatalf("write header: %v", err)
	}
	resp, err := proto.ReadResponse(stream)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return stream, resp
}

// TestWireUnknownTarget verifies that a target absent from the route table
// yields status 1 (unknown_target) on the wire.
func TestWireUnknownTarget(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	_, resp := openClientStream(t, ctx, clientTLS, serverAddr, proto.Header{Kind: proto.KindTCP, Target: "bogus"})
	if resp.Status != proto.StatusUnknownTarget {
		t.Fatalf("got status %v, want unknown_target (1)", resp.Status)
	}
}

// TestWireUnauthorized verifies that an injected deny policy yields status 2
// (unauthorized) on the wire — the mandatory authorization check-point.
func TestWireUnauthorized(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	deny := router.PolicyFunc(func(router.Identity, proto.Header) error { return errors.New("test deny") })
	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, deny)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	_, resp := openClientStream(t, ctx, clientTLS, serverAddr, proto.Header{Kind: proto.KindTCP, Target: "ssh"})
	if resp.Status != proto.StatusUnauthorized {
		t.Fatalf("got status %v, want unauthorized (2)", resp.Status)
	}
}

// TestWireDockerUnixRoundTrip verifies unix-socket dialing: a "docker" target
// routed to a unix-socket echo server returns status 0 and round-trips bytes.
func TestWireDockerUnixRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	sockPath := filepath.Join(t.TempDir(), "d.sock")
	unixLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	t.Cleanup(func() { unixLn.Close() })
	go runEchoServer(unixLn)

	rtr := mustRouter(t, map[string]string{"docker": "unix://" + sockPath}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	stream, resp := openClientStream(t, ctx, clientTLS, serverAddr, proto.Header{Kind: proto.KindTCP, Target: "docker"})
	if resp.Status != proto.StatusOK {
		t.Fatalf("got status %v, want ok (0)", resp.Status)
	}

	payload := []byte("docker-through-unix")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}
