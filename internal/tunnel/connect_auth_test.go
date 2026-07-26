package tunnel

// Real-QUIC test for the agent-rejects-client auth path through Establish.
// This path cannot be covered by the in-memory transport harness because the
// classification relies on *quic.TransportError from a real pin mismatch.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// genIdentityForAuth is a white-box copy of mustGenIdentity for use in
// package-tunnel tests, where the integration_test.go helpers are not
// visible (they live in the package tunnel_test compilation unit).
func genIdentityForAuth(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("pin for key: %v", err)
	}
	return key, pin
}

// TestEstablish_AgentRejectsClient verifies that when the agent is configured
// to authorize a different client pin (not ours), connManager.Establish returns
// transport.ErrAuthFailed so the caller can map it to exit 4 rather than the
// generic exit 1.
//
// With QUIC + TLS 1.3 the client's own handshake completes before the agent's
// rejection arrives, so the failure surfaces during control.Open — not at Dial.
// This test exercises that post-handshake classification path in
// openControlAndRecord.
func TestEstablish_AgentRejectsClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := genIdentityForAuth(t)
	clientKey, _ := genIdentityForAuth(t)     // our identity
	_, authorizedPin := genIdentityForAuth(t) // a third identity the agent authorizes

	// The agent accepts the authorized pin but NOT the client's pin.
	serverTLS, err := identity.ServerTLS(serverKey, []string{authorizedPin})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	// The client trusts the real server pin (so our handshake succeeds).
	clientTLS, err := identity.ClientTLS(clientKey, serverPin)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}

	// Start a real QUIC agent.
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

	ln, err := serverTr.Listen()
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go Serve(ctx, ln, rtr) //nolint:errcheck

	// Build a client-side QUIC transport.
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { clientUDP.Close() })

	clientTr, err := transport.NewQUICTransport(clientUDP, clientTLS, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { clientTr.Close() })

	mgr := &connManager{
		t:          clientTr,
		serverAddr: ln.Addr().String(),
	}

	_, err = mgr.Establish(ctx)
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("Establish with rejected client pin: got %v, want transport.ErrAuthFailed", err)
	}
}
