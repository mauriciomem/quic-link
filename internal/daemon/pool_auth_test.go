package daemon_test

// Real-QUIC test for F2: the pool must give up retrying a permanently-rejected
// pin instead of looping forever.
//
// The in-memory transport harness cannot produce a *quic.TransportError, so
// this test uses real QUIC over the loopback interface (127.0.0.1:0).
//
// The old isAuthFailed used transport.AuthError(err), which does errors.As for
// *quic.TransportError. tunnel.OpenControl — the shared post-dial helper used
// by both the foreground connect path and the daemon pool — already translates
// the TLS-alert TransportError into transport.ErrAuthFailed (the sentinel)
// before returning. The resulting error satisfies errors.Is(err, ErrAuthFailed)
// but NOT errors.As(err, &*quic.TransportError), so the old isAuthFailed
// returned false and the pool retried indefinitely.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestPool_GivesUpOnPermanentAuthFailure exercises the agent-rejects-client
// path through the daemon session pool. After the client's own TLS handshake
// completes, the agent closes the connection with a TLS alert because the
// client's pin is not in the authorized set. tunnel.OpenControl translates that
// to transport.ErrAuthFailed (the sentinel). The pool must detect this,
// stop retrying, and reflect a terminal (non-"connecting") state.
//
// Asserts:
//
//	(a) pool.Get returns an error wrapping transport.ErrAuthFailed (the loop
//	    stopped rather than retrying indefinitely).
//	(b) The session state after the giveup is NOT "connecting" — a permanently-
//	    rejected pin must not be presented as a transient reconnect condition.
func TestPool_GivesUpOnPermanentAuthFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Generate identities.
	serverKey, serverPin := genPoolIdentity(t)
	clientKey, _ := genPoolIdentity(t)
	_, authorizedPin := genPoolIdentity(t) // what the agent actually accepts

	// Agent accepts authorizedPin, NOT clientKey's pin.
	serverTLS, err := identity.ServerTLS(serverKey, []string{authorizedPin})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	// Client trusts the real server pin (so the client-side handshake completes).
	clientTLS, err := identity.ClientTLS(clientKey, serverPin)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}

	// Start the agent.
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
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	// Client transport.
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

	// Wire a minimal config with one enabled server pointing at the agent.
	serverAddr := ln.Addr().String()
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"rejecting-agent": {
			Addr: serverAddr,
		},
	}

	// Use a zero-delay reconnect policy so the loop burns through quickly
	// rather than waiting 250 ms → 500 ms → … before the test can observe the
	// giveup. The zero delay makes the test fast without hiding the bug.
	zeroPolicy := zeroBackoffPolicy{}

	makeTransport := func(_ string, _ config.Server) (transport.Transport, error) {
		return clientTr, nil
	}

	pool, err := daemon.NewRealPool(
		ctx,
		cfg,
		makeTransport,
		zeroPolicy,
		newFixedClock(),
		nil, // no boundPorts needed for this test
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// (a) pool.Get must return an auth-failure error (not block forever).
	// We give up to 10 seconds for the pool to detect the rejection and stop.
	getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
	defer getCancel()

	_, getErr := pool.Get(getCtx, "rejecting-agent")
	if getErr == nil {
		t.Fatal("pool.Get: expected auth-failure error, got nil")
	}
	if !errors.Is(getErr, transport.ErrAuthFailed) {
		t.Fatalf("pool.Get: error does not wrap ErrAuthFailed: %v", getErr)
	}

	// (b) session state must NOT be "connecting" after the loop stops.
	// "connecting" means "transient, will recover" — that is the wrong signal
	// for a permanently-rejected pin.
	states := pool.State()
	if len(states) == 0 {
		t.Fatal("pool.State: no states returned")
	}
	for _, s := range states {
		if s.State == "connecting" {
			t.Errorf("session %q still reports 'connecting' after permanent auth failure; "+
				"a permanently-rejected pin must not be presented as transient", s.Name)
		}
	}
}

// genPoolIdentity generates a fresh Ed25519 identity (key + pin) for use in
// pool auth tests. This is a package-local helper (distinct from the tunnel
// package's helpers) so daemon_test.go stays self-contained.
func genPoolIdentity(t *testing.T) (ed25519.PrivateKey, string) {
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

// zeroBackoffPolicy is a ReconnectPolicy that returns zero backoff on every
// attempt, making the run-loop burn through quickly in tests. It also returns
// a very short StableAfter so the backoff counter never resets due to uptime.
type zeroBackoffPolicy struct{}

func (zeroBackoffPolicy) Backoff(_ int) time.Duration { return 0 }
func (zeroBackoffPolicy) StableAfter() time.Duration  { return time.Second }
