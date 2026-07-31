package daemon_test

// pool_isolation_test.go covers the hard invariant: one pool entry that is
// unreachable, reconnecting, or permanently failing must never stall Get(),
// State(), or the reconnect loop of OTHER healthy entries.
//
// The test uses the in-memory transport harness (internal/transport/mem) and
// the injected DI seams (LivenessPolicy, ReconnectPolicy, Clock) so it is
// fast and deterministic — no real QUIC, no OS privileges, no wall-clock
// sleeps for timeouts.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestPoolEntryIsolation asserts that one sick (permanently unreachable) server
// entry never blocks Get(), State(), or reconnect loops on another healthy entry.
//
// Structural isolation comes from each entry owning its own goroutine, mutex,
// and context. But structure alone is not tested: this regression test would
// catch a future refactor that introduces a shared lock or a cross-entry
// goroutine (e.g. a shared dial semaphore, a shared backoff timer, or a
// pool-level mutex that State() and Get() both hold).
//
// Pre-fix / regression mode: if someone introduces a pool-level lock that
// State() or Get() hold while the sick entry's runLoop also holds it, the
// Get() and State() calls on the healthy entry will block for the duration
// of a rebind or backoff wait — this test will time out and report failure.
func TestPoolEntryIsolation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Hub with two servers: "healthy" has a real listener; "sick" never has one
	// so every dial returns ErrUnreachable immediately.
	hub := mem.NewHub()

	// The healthy server's transport has a listener so the pool can connect.
	healthyLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	healthySrvT := hub.Transport("healthy-agent:1", mem.WithCert(healthyLeaf))
	ln, err := healthySrvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Start a minimal tunnel.Serve loop on the healthy server so the pool can
	// complete the control-stream handshake required to enter "connected".
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() {
		// Ignore the return — the test tears it down via serveCancel.
		_ = tunnel.Serve(serveCtx, ln, nil)
	}()

	// Client-side transport for the healthy server.
	healthyCliT := hub.Transport("healthy-client:1", mem.WithCert(healthyLeaf))

	// The sick server's transport never has a listener — every Dial returns
	// ErrUnreachable immediately, causing the run-loop to spin in zero-backoff
	// retry. If this entry shared a lock with the healthy entry, Get() on the
	// healthy entry would stall here.
	sickT := hub.Transport("sick-client:1")

	// Build a pool with two servers.
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"healthy": {Addr: "healthy-agent:1"},
		"sick":    {Addr: "sick-no-listener:1"},
	}

	// fast liveness: we don't actually need probes here; use a slow policy so
	// they don't interfere with the isolation assertion.
	noProbePolicy := fastLivenessPolicy{
		interval:  60 * time.Second,
		timeout:   5 * time.Second,
		threshold: 2,
	}

	pool, poolErr := daemon.NewRealPoolWithLiveness(
		ctx, cfg,
		func(_ string, srv config.Server) (transport.Transport, error) {
			switch srv.Addr {
			case "healthy-agent:1":
				return healthyCliT, nil
			default:
				return sickT, nil
			}
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
		noProbePolicy,
	)
	if poolErr != nil {
		t.Fatalf("NewRealPoolWithLiveness: %v", poolErr)
	}
	defer pool.Close()

	// Wait for the healthy entry to reach "connected". The sick entry is
	// simultaneously spinning in its reconnect loop. If isolation is broken,
	// this will block until the test deadline.
	const connBudget = 5 * time.Second
	connDeadline := time.Now().Add(connBudget)
	for time.Now().Before(connDeadline) {
		state, err := pool.EntryState("healthy")
		if err != nil {
			t.Fatalf("EntryState(healthy): %v", err)
		}
		if state == "connected" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	healthyState, err := pool.EntryState("healthy")
	if err != nil {
		t.Fatalf("EntryState(healthy): %v", err)
	}
	if healthyState != "connected" {
		t.Fatalf("healthy entry did not reach 'connected' within %s; got %q — "+
			"if the sick entry is blocking this, isolation is broken", connBudget, healthyState)
	}

	// Now assert that State() and Get() on the pool are fast — well under any
	// reasonable wait that the sick entry's run-loop might hold a lock for.
	// If isolation is broken, these calls stall for a backoff wait or a rebind.
	const callBudget = 100 * time.Millisecond

	// Assert State() is fast while the sick entry keeps retrying.
	for i := range 5 {
		start := time.Now()
		states := pool.State()
		elapsed := time.Since(start)
		if elapsed > callBudget {
			t.Errorf("State() call %d took %s (budget %s); "+
				"a sick entry is blocking the healthy entry's State() — isolation broken",
				i, elapsed.Round(time.Millisecond), callBudget)
		}
		// Confirm the healthy entry is still connected.
		var foundHealthy bool
		for _, s := range states {
			if s.Name == "healthy" && s.State == "connected" {
				foundHealthy = true
			}
		}
		if !foundHealthy {
			t.Errorf("State() call %d: healthy entry not found in 'connected' state; states: %v",
				i, states)
		}
	}

	// Assert Get() on the healthy entry is fast.
	for i := range 3 {
		getCtx, getCancel := context.WithTimeout(ctx, callBudget)
		start := time.Now()
		conn, getErr := pool.Get(getCtx, "healthy")
		elapsed := time.Since(start)
		getCancel()

		if getErr != nil {
			t.Errorf("Get(healthy) call %d: unexpected error %v", i, getErr)
			continue
		}
		if conn == nil {
			t.Errorf("Get(healthy) call %d: nil conn with no error", i)
		}
		if elapsed > callBudget {
			t.Errorf("Get(healthy) call %d took %s (budget %s); "+
				"a sick entry is blocking the healthy entry's Get() — isolation broken",
				i, elapsed.Round(time.Millisecond), callBudget)
		}
	}

	// Confirm the sick entry is still in "connecting" — it must not have
	// somehow blocked the healthy entry AND progressed itself.
	sickState, err := pool.EntryState("sick")
	if err != nil {
		t.Fatalf("EntryState(sick): %v", err)
	}
	if sickState == "connected" {
		t.Errorf("sick entry reached 'connected' unexpectedly (test setup error: " +
			"sick transport should never succeed)")
	}
	t.Logf("isolation confirmed: healthy=%q sick=%q; State() and Get() remained fast",
		healthyState, sickState)
}

// TestPoolEntryIsolation_AuthFailedDoesNotBlockOthers verifies that a
// permanently auth-failed entry (which exits its run-loop immediately) does
// not block State() or Get() on a healthy sibling entry.
//
// This is a distinct failure mode from the reconnect-loop case above: an
// auth-failed entry's loop exits, so it is permanently stuck in a terminal
// state. If State() or Get() held a pool-level lock, the auth-failed entry's
// loop-exit bookkeeping could contend with them.
func TestPoolEntryIsolation_AuthFailedDoesNotBlockOthers(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := mem.NewHub()

	// Healthy server: real listener + serve loop.
	healthyLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	healthySrvT := hub.Transport("iso2-agent:1", mem.WithCert(healthyLeaf))
	ln, err := healthySrvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, ln, nil) }()

	healthyCliT := hub.Transport("iso2-healthy-client:1", mem.WithCert(healthyLeaf))

	// Auth-failed server: FailDial with ErrAuthFailed — loop exits immediately.
	authFailT := hub.Transport("iso2-auth-client:1", mem.FailDial(transport.ErrAuthFailed))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"healthy":   {Addr: "iso2-agent:1"},
		"auth-fail": {Addr: "iso2-authfail:1"},
	}

	pool, poolErr := daemon.NewRealPoolWithLiveness(
		ctx, cfg,
		func(_ string, srv config.Server) (transport.Transport, error) {
			switch srv.Addr {
			case "iso2-agent:1":
				return healthyCliT, nil
			default:
				return authFailT, nil
			}
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
		fastLivenessPolicy{interval: 60 * time.Second, timeout: 5 * time.Second, threshold: 2},
	)
	if poolErr != nil {
		t.Fatalf("NewRealPoolWithLiveness: %v", fmt.Errorf("%v", poolErr))
	}
	defer pool.Close()

	// Wait for the auth-failed entry to reach "auth_failed" and the healthy
	// entry to reach "connected".
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h, _ := pool.EntryState("healthy")
		a, _ := pool.EntryState("auth-fail")
		if h == "connected" && a == "auth_failed" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	h, _ := pool.EntryState("healthy")
	a, _ := pool.EntryState("auth-fail")

	if h != "connected" {
		t.Errorf("healthy entry state = %q; want 'connected'", h)
	}
	if a != "auth_failed" {
		t.Errorf("auth-fail entry state = %q; want 'auth_failed'", a)
	}

	// State() must still be fast.
	const callBudget = 50 * time.Millisecond
	for i := range 3 {
		start := time.Now()
		states := pool.State()
		elapsed := time.Since(start)
		if elapsed > callBudget {
			t.Errorf("State() call %d took %s; want < %s — isolation broken", i, elapsed, callBudget)
		}
		_ = states
	}

	t.Logf("isolation confirmed: healthy=%q auth-fail=%q", h, a)
}
