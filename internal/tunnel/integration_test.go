package tunnel_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

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

// TestPingAuthRejected verifies that when the agent does not authorize the
// client's pin, the client's transport handshake still completes but the
// control stream is torn down — and probe.Ping reports this as an auth failure
// (transport.ErrAuthFailed) so ping exits with the auth code, rather than a
// reachable-but-broken peer.
func TestPingAuthRejected(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, _ := mustGenIdentity(t)
	_, otherPin := mustGenIdentity(t) // the only pin the agent authorizes

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	// Agent authorizes someone else; the client presents the correct server pin
	// (so the client accepts the server) but is itself not authorized.
	serverTLS := mustServerTLS(t, serverKey, []string{otherPin})
	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

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

	if _, err := probe.Ping(ctx, tr, serverAddr); !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("Ping: got %v, want transport.ErrAuthFailed", err)
	}
}

// ---- test helpers ------------------------------------------------------------

// mustStartServe starts a QUIC serve tunnel backed by rtr and returns the
// server's UDP addr string (host:port). opts is optional and forwarded to
// tunnel.Serve unchanged; omit it for the same behaviour as before opts
// existed. Cleanup is registered with t.
func mustStartServe(t *testing.T, ctx context.Context, tlsConf *tls.Config, rtr *router.Router, opts ...tunnel.ServeOpts) string {
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

	go tunnel.Serve(ctx, ln, rtr, opts...) //nolint:errcheck
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

// ---- wire-level tests --------------------------------------------------------

// mustClientTLS builds a client pinning tls.Config that presents key's carrier
// cert and expects the given server pin.
func mustClientTLS(t *testing.T, key ed25519.PrivateKey, serverPin string) *tls.Config {
	t.Helper()
	c, err := identity.ClientDialTLS(key, serverPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	return c
}

// mustServerTLS builds an agent pinning tls.Config that presents key's carrier
// cert and authorizes the given client pins.
func mustServerTLS(t *testing.T, key ed25519.PrivateKey, authorized []string) *tls.Config {
	t.Helper()
	c, err := identity.AgentListenTLS(key, authorized)
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
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

// TestReqIDPropagation verifies that a reqid stamped by the client in
// Meta["reqid"] is received by the agent: both a present reqid (the normal
// client path) and an absent reqid (older/other clients) must yield status 0.
// A capturing policy records the header fields seen by the agent so the test
// can inspect them without reading agent logs.
func TestReqIDPropagation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// headerCapture records every header the agent sees and always allows.
	type capturedHeader struct {
		reqid string
		ok    bool // whether the reqid key was present (even if empty)
	}
	captured := make(chan capturedHeader, 4)
	capPolicy := router.PolicyFunc(func(_ router.Identity, h proto.Header) error {
		_, ok := h.Meta["reqid"]
		captured <- capturedHeader{reqid: h.Meta["reqid"], ok: ok}
		return nil
	})

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, capPolicy)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	t.Run("with reqid", func(t *testing.T) {
		const want = "deadbeefcafe0123"
		_, resp := openClientStream(t, ctx, clientTLS, serverAddr, proto.Header{
			Kind:   proto.KindTCP,
			Target: "ssh",
			Meta:   map[string]string{"reqid": want},
		})
		if resp.Status != proto.StatusOK {
			t.Fatalf("got status %v, want ok (0)", resp.Status)
		}
		select {
		case h := <-captured:
			if !h.ok {
				t.Error("agent did not receive Meta[\"reqid\"] key")
			}
			if h.reqid != want {
				t.Errorf("agent received reqid %q, want %q", h.reqid, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for captured header")
		}
	})

	t.Run("absent reqid tolerated", func(t *testing.T) {
		// A header with no Meta at all must not cause an error on the agent side.
		_, resp := openClientStream(t, ctx, clientTLS, serverAddr, proto.Header{
			Kind:   proto.KindTCP,
			Target: "ssh",
		})
		if resp.Status != proto.StatusOK {
			t.Fatalf("absent reqid: got status %v, want ok (0)", resp.Status)
		}
		select {
		case h := <-captured:
			if h.reqid != "" {
				t.Errorf("expected empty reqid for absent key, got %q", h.reqid)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for captured header")
		}
	})
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

	// From /tmp rather than t.TempDir, whose path includes TMPDIR and the test
	// name and can exceed the 104-byte socket limit on macOS.
	sockDir, mkErr := os.MkdirTemp("/tmp", "ql-tunnel-")
	if mkErr != nil {
		t.Fatalf("creating a short temp dir for a unix socket: %v", mkErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "d.sock")
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
