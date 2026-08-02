package tunnel_test

import (
	"context"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// Under pinning, a peer holding the wrong key never finishes the handshake, so
// almost every role confusion is already refused as an authentication failure.
// The one that gets through is a peer holding OUR key, which happens when an
// operator copies one identity to both ends. Then neither side can tell which
// role the other is playing, and that is worth saying plainly rather than
// letting it fail somewhere further downstream.

// TestSameIdentityAsPeer covers the predicate itself, including that an empty
// own-pin disables the check rather than matching everything.
func TestSameIdentityAsPeer(t *testing.T) {
	tests := []struct {
		name   string
		ownPin string
		peer   string
		want   bool
	}{
		{"peer using our identity", "PIN-A", "PIN-A", true},
		{"peer using its own identity", "PIN-A", "PIN-B", false},
		{"check disabled when we do not know our own pin", "", "PIN-B", false},
		{"an unknown peer never counts as us", "PIN-A", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tunnel.SameIdentityAsPeer(tt.ownPin, router.Identity{Pin: tt.peer})
			if got != tt.want {
				t.Errorf("SameIdentityAsPeer(%q, %q) = %v, want %v",
					tt.ownPin, tt.peer, got, tt.want)
			}
		})
	}
}

// TestServeConn_RefusesAPeerUsingOurIdentity: the connection is closed rather
// than served, so a shared key cannot quietly produce a working-looking tunnel
// where neither end is enforcing what it should.
func TestServeConn_RefusesAPeerUsingOurIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hub := mem.NewHub()
	shared, sharedPin, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	// Both ends carry the same identity, which is exactly the misconfiguration.
	agentT := hub.Transport("dup-agent:1", mem.WithCert(shared))
	ln, err := agentT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go func() { _ = tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{OwnPin: sharedPin}) }()

	clientT := hub.Transport("dup-client:1", mem.WithCert(shared))
	conn, err := clientT.Dial(ctx, "dup-agent:1")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	select {
	case <-conn.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("a peer using our own identity was served instead of refused")
	}

	cause := context.Cause(conn.Context())
	if !transport.IsRoleMismatch(cause) {
		t.Errorf("close cause = %v, want a role mismatch", cause)
	}
}

// TestRoleMismatch_IsNotAnAuthenticationFailure is the distinction that keeps
// an operator pointed the right way. A rejected pin means the credentials are
// wrong and should be re-exchanged; a role collision means the credentials were
// accepted and the problem is that there is only one of them. Reporting the
// second as the first sends someone off re-pasting keys that are already fine.
func TestRoleMismatch_IsNotAnAuthenticationFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hub := mem.NewHub()
	shared, sharedPin, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	agentT := hub.Transport("dup2-agent:1", mem.WithCert(shared))
	ln, err := agentT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go func() { _ = tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{OwnPin: sharedPin}) }()

	conn, err := hub.Transport("dup2-client:1", mem.WithCert(shared)).Dial(ctx, "dup2-agent:1")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("connection was not closed")
	}

	cause := context.Cause(conn.Context())
	if transport.IsAuthFailed(cause) {
		t.Error("a role collision was reported as an authentication failure; " +
			"an operator would go and re-exchange pins that are already correct")
	}
	if !transport.IsRoleMismatch(cause) {
		t.Errorf("close cause = %v, want a role mismatch", cause)
	}
}

// TestServeConn_ServesADistinctPeerNormally is the control: the refusal must
// depend on the identity actually colliding, not fire whenever OwnPin is set.
func TestServeConn_ServesADistinctPeerNormally(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hub := mem.NewHub()
	agentCert, agentPin, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	clientCert, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	ln, err := hub.Transport("ok-agent:1", mem.WithCert(agentCert)).Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go func() { _ = tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{OwnPin: agentPin}) }()

	conn, err := hub.Transport("ok-client:1", mem.WithCert(clientCert)).Dial(ctx, "ok-agent:1")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-conn.Context().Done():
		t.Fatalf("a peer with its own distinct identity was refused: %v",
			context.Cause(conn.Context()))
	case <-time.After(500 * time.Millisecond):
	}
	_ = conn.CloseWithError(0, "test done")
}
