package main

// stdio_auth_test.go — follow-up fix verification for the loopback-smoke
// finding: stdioRun's direct-QUIC path called control.Open directly instead
// of the shared tunnel.OpenControl classifier that ping and the daemon pool
// use, so an auth-rejected pin exited 1 instead of 4. This test drives the
// real direct-QUIC path (no daemon) end-to-end and asserts the resolved
// process exit code.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestStdioRun_AuthRejected_ExitCode4 drives stdioRun's direct-QUIC path
// against a real QUIC agent that authorizes a DIFFERENT pin than the client
// presents. The client's own handshake completes (it trusts the real server
// pin) but the agent rejects the client's pin post-handshake — the same
// agent-rejects-client shape as TestPingAuthRejected
// (internal/tunnel/integration_test.go) and
// TestPool_GivesUpOnPermanentAuthFailure (internal/daemon/pool_auth_test.go).
// Asserts the resolved process exit code is 4, not 1.
func TestStdioRun_AuthRejected_ExitCode4(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := stdioAuthGenIdentity(t)
	clientKey, _ := stdioAuthGenIdentity(t)
	_, authorizedPin := stdioAuthGenIdentity(t) // agent authorizes this pin, NOT the client's

	serverTLS, err := identity.AgentListenTLS(serverKey, []string{authorizedPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}

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
	ln, err := serverTr.Listen()
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	// Write the client's key to a temp file — stdioRun (via clientTLSFromFlags)
	// loads the key from disk, mirroring the real CLI invocation.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "client_key.pem")
	if err := identity.WriteKey(keyFile, clientKey); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	err = stdioRun(ctx, ln.Addr().String(), "ssh", keyFile, serverPin)
	if err == nil {
		t.Fatal("stdioRun: expected an error for a rejected pin, got nil")
	}

	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("stdioRun error does not wrap transport.ErrAuthFailed: %v", err)
	}

	got := exitCodeForError(err)
	if got != 4 {
		t.Errorf("exitCodeForError(stdioRun auth-rejected) = %d, want 4 (err=%v)", got, err)
	}
}

func stdioAuthGenIdentity(t *testing.T) (ed25519.PrivateKey, string) {
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
