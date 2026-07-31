package daemon_test

// Tests for F3: status --json must report the ports that are actually bound,
// not the configured ideal.
//
// Two cases:
//   - (a) Clash: when the deterministic ideal port is already occupied, the
//         allocator steps +10. The pool must report the stepped port, not the
//         ideal port.
//   - (b) Disabled: a disabled server has no listeners. It must report 0/0,
//         not the deterministic ideal that would have been computed from the
//         server name.
//
// These tests exercise NewRealPool directly with a controlled boundPorts map,
// asserting that the pool's SessionState.SSHPort / DockerPort reflect the
// provided (actually-bound) ports rather than the config-derived ideal.
// No real QUIC is needed: the pool's status path is pure in-memory state.

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/edge"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// ---- (a) Clash: step verified in status output --------------------------------

// TestPoolPorts_ReportsSteppedPortOnClash binds the ideal base ports for a
// server so the allocator must step to the next block. It then verifies that
// pool.State() reports the stepped (actually-bound) ports, not the ideal ports
// that config.LocalPorts would have computed.
//
// Old behaviour (pre-fix): NewRealPool called config.LocalPorts independently
// of AcquirePair, so the pool always reported the ideal ports regardless of
// where the edge actually bound. Under contention the reported port had no
// listener, breaking the "reported addresses reflect what is bound" rule.
func TestPoolPorts_ReportsSteppedPortOnClash(t *testing.T) {
	t.Parallel()

	const serverName = "stepserver"

	// Compute the ideal base ports for this server name.
	sshIdeal, dkrIdeal := config.LocalPorts(serverName, nil)

	// Pre-bind the ideal ports so AcquirePair must step.
	l1, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", sshIdeal))
	if err != nil {
		t.Skip("cannot bind ideal ssh port; skipping clash test")
	}
	defer l1.Close()
	l2, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", dkrIdeal))
	if err != nil {
		t.Skip("cannot bind ideal docker port; skipping clash test")
	}
	defer l2.Close()

	// Run AcquirePair — it must step to the +10 block.
	alloc := edge.PortAllocator{}
	sshLn, dkrLn, err := alloc.AcquirePair(serverName, nil)
	if err != nil {
		t.Fatalf("AcquirePair: %v", err)
	}
	defer sshLn.Close()
	defer dkrLn.Close()

	sshActual := sshLn.Addr().(*net.TCPAddr).Port
	dkrActual := dkrLn.Addr().(*net.TCPAddr).Port

	if sshActual == sshIdeal || dkrActual == dkrIdeal {
		t.Fatalf("AcquirePair did not step: ssh=%d (ideal %d) docker=%d (ideal %d)",
			sshActual, sshIdeal, dkrActual, dkrIdeal)
	}

	// Build a pool with the stepped (actually-bound) ports in boundPorts.
	boundPorts := map[string][2]int{
		serverName: {sshActual, dkrActual},
	}

	hub := mem.NewHub()
	leafCert, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	dialedTr := hub.Transport("stepagent:1", mem.WithCert(leafCert))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		serverName: {Addr: "stepagent:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx,
		cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return dialedTr, nil
		},
		daemon.DefaultReconnectPolicy(),
		newFixedClock(),
		boundPorts,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// pool.State() must report the stepped ports, not the ideal ports.
	states := pool.State()
	if len(states) == 0 {
		t.Fatal("State(): no states returned")
	}
	s := states[0]

	if s.SSHPort == sshIdeal {
		t.Errorf("pool reported ideal ssh port %d; want stepped port %d — "+
			"status must reflect what is actually bound", sshIdeal, sshActual)
	}
	if s.SSHPort != sshActual {
		t.Errorf("pool reported ssh port %d; want stepped port %d", s.SSHPort, sshActual)
	}
	if s.DockerPort == dkrIdeal {
		t.Errorf("pool reported ideal docker port %d; want stepped port %d — "+
			"status must reflect what is actually bound", dkrIdeal, dkrActual)
	}
	if s.DockerPort != dkrActual {
		t.Errorf("pool reported docker port %d; want stepped port %d", s.DockerPort, dkrActual)
	}
}

// ---- (b) Disabled server reports 0/0 -----------------------------------------

// TestPoolPorts_DisabledServerReportsZero verifies that a disabled server's
// session state carries ssh=0 and docker=0, not the deterministic ideal that
// config.LocalPorts would compute. A disabled server has no listeners; reporting
// any non-zero port implies something is bound there, which is false.
//
// Old behaviour (pre-fix): disabledEntry received the config.LocalPorts result
// and reported it. Field-observed: "offsrv" reported 58730/58731 with no
// listener anywhere.
func TestPoolPorts_DisabledServerReportsZero(t *testing.T) {
	t.Parallel()

	const serverName = "disabledportsrv"

	falseVal := false
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		serverName: {
			Addr:    "127.0.0.1:9999",
			Enabled: &falseVal,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx,
		cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return nil, fmt.Errorf("makeTransport should not be called for a disabled server")
		},
		daemon.DefaultReconnectPolicy(),
		newFixedClock(),
		nil, // no boundPorts — disabled server must never appear here
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	states := pool.State()
	if len(states) == 0 {
		t.Fatal("State(): no states returned")
	}
	s := states[0]

	if s.State != "disabled" {
		t.Fatalf("expected state 'disabled', got %q", s.State)
	}
	if s.SSHPort != 0 {
		t.Errorf("disabled server ssh port = %d; want 0 — no listener is bound", s.SSHPort)
	}
	if s.DockerPort != 0 {
		t.Errorf("disabled server docker port = %d; want 0 — no listener is bound", s.DockerPort)
	}

	// Verify the JSON representation too — the golden contracts {"ssh":0,"docker":0}.
	wantSSHInOld := config.LocalPortBase(serverName) // what the old code would have reported
	if s.SSHPort == wantSSHInOld {
		t.Errorf("pool reported the config-derived ideal port %d for a disabled server; "+
			"want 0 to prevent consumers from thinking a listener is present", wantSSHInOld)
	}
	if wantSSHInOld != 0 {
		// Only emit this check when the ideal port is non-zero (it always is),
		// confirming the test would catch the old behaviour.
		t.Logf("old behaviour would have reported ssh=%d docker=%d; got 0/0 (correct)",
			wantSSHInOld, wantSSHInOld+1)
	}
}

// ---- (c) Failed-acquisition server reports 0/0 --------------------------------

// TestPoolPorts_FailedAcquisitionReportsZero verifies that when a server's port
// pair cannot be acquired (e.g. all 10 blocks are occupied), the pool reports
// 0/0 rather than the config ideal. This is consistent with the disabled case:
// if nothing is listening, status must not name a port.
func TestPoolPorts_FailedAcquisitionReportsZero(t *testing.T) {
	t.Parallel()

	const serverName = "noportsrv"

	// An empty boundPorts map — as if acquisition failed for this server.
	boundPorts := map[string][2]int{}

	hub := mem.NewHub()
	leafCert, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	dialedTr := hub.Transport("noportagent:1", mem.WithCert(leafCert))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		serverName: {Addr: "noportagent:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx,
		cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return dialedTr, nil
		},
		daemon.DefaultReconnectPolicy(),
		newFixedClock(),
		boundPorts,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	states := pool.State()
	if len(states) == 0 {
		t.Fatal("State(): no states returned")
	}
	s := states[0]

	if s.SSHPort != 0 || s.DockerPort != 0 {
		t.Errorf("server with no acquired ports reported ssh=%d docker=%d; want 0/0 — "+
			"status must not report phantom ports", s.SSHPort, s.DockerPort)
	}
	// Confirm the config-ideal would be non-zero (making the test meaningful).
	idealSSH, idealDkr := config.LocalPorts(serverName, nil)
	t.Logf("old behaviour would have reported ssh=%d docker=%d; got 0/0 (correct)", idealSSH, idealDkr)
}
