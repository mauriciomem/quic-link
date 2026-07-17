package tunnel_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// dialConn dials the agent and returns an established client-side QUIC
// connection. Cleanup is registered with t.
func dialConn(t *testing.T, ctx context.Context, tlsConf *tls.Config, serverAddr string) transport.Conn {
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

	conn, err := tr.Dial(ctx, serverAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck
	return conn
}

// TestControlPingE2E drives a real control stream over QUIC: open it, then time
// a Ping RPC. Exercises the agent's serveControl branch end to end.
func TestControlPingE2E(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client")
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()

	rtt, err := client.PingRTT(ctx)
	if err != nil {
		t.Fatalf("PingRTT: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("PingRTT returned non-positive rtt: %v", rtt)
	}
	t.Logf("control ping rtt=%v", rtt)
}

// TestControlSecondStreamRejected verifies that a second control stream on the
// same session is refused with status 5.
func TestControlSecondStreamRejected(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)

	// First control stream (established, kept open).
	client, err := control.Open(ctx, conn, "test-client")
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()

	// Second control stream on the SAME connection → status 5.
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open second control stream: %v", err)
	}
	if err := proto.WriteHeader(stream, proto.Header{
		Kind: proto.KindControl,
		Meta: map[string]string{"proto": "1"},
	}); err != nil {
		t.Fatalf("write second control header: %v", err)
	}
	resp, err := proto.ReadResponse(stream)
	if err != nil {
		t.Fatalf("read second control response: %v", err)
	}
	if resp.Status != proto.StatusBadHeader {
		t.Fatalf("second control: got status %v, want bad_header (5)", resp.Status)
	}
}

// TestControlBadProto verifies that a control header with proto != "1" yields
// status 6 and the agent closes the session.
func TestControlBadProto(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	if err := proto.WriteHeader(stream, proto.Header{
		Kind: proto.KindControl,
		Meta: map[string]string{"proto": "2"},
	}); err != nil {
		t.Fatalf("write control header: %v", err)
	}

	// The agent replies status 6 then closes the session 0x04. QUIC may deliver
	// the CONNECTION_CLOSE before the response frame, so either signal is a
	// valid "bad proto" indication: a status-6 frame, or a read error from the
	// session teardown. What MUST hold is that the session gets closed.
	if resp, rerr := proto.ReadResponse(stream); rerr == nil && resp.Status != proto.StatusUnsupportedVersion {
		t.Fatalf("got status %v, want unsupported_version (6) or a teardown error", resp.Status)
	}

	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session was not closed after bad control proto")
	}
}
