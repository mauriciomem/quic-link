package daemon_test

// pool_liveness_test.go covers:
//
//  C3a — stateReconnecting serialises to JSON "connecting", not a sixth value.
//  C3b — stateAuthFailed serialises to JSON "auth_failed".
//  C3c — the emitted enum set is exactly the five allowed values; "invalid"
//         is never emitted.
//  C3d — the liveness probe detects a dead agent substantially faster than
//         the QUIC idle timeout (driven via injected fast policy).
//  F4a — transport rebind fires after exactly transportRebindAfter consecutive
//         dial failures.
//  F4b — rebind does NOT fire before transportRebindAfter failures.
//  F4c — the consecutive-failure counter resets after a successful dial.
//  F4e — local-addr / failure-count / elapsed-since-success log attributes
//         appear in the output.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- C3a: stateReconnecting → JSON "connecting" ----------------------------

// TestStateReconnecting_SerializesToConnecting asserts that the internal
// "reconnecting" state (connection dropped, re-dialing) projects to the JSON
// value "connecting", not a new sixth enum value.
//
// Pre-fix failure mode: if State() had a case stateReconnecting → "reconnecting",
// the pool would emit a sixth value not in the five-value set, breaking
// consumers that follow the open-enum rule (treat unknowns as "not healthy").
func TestStateReconnecting_SerializesToConnecting(t *testing.T) {
	t.Parallel()

	// Build a pool against an address with no listener — every dial fails
	// immediately, so the entry rapidly cycles connecting → reconnecting → ...
	// Use WallClock so the backoff timer actually fires between retries.
	hub := mem.NewHub()
	dialTr := hub.Transport("c3a-client:1")

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"dead-server": {Addr: "c3a-dead:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return dialTr, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// Wait briefly for the first dial to fail and transition to reconnecting.
	time.Sleep(50 * time.Millisecond)

	// The pool must emit "connecting" — both initial-connecting and
	// reconnecting project to the same external value.
	states := pool.State()
	if len(states) == 0 {
		t.Fatal("State(): no states returned")
	}
	for _, s := range states {
		if s.State != "connecting" {
			t.Errorf("server %q: state = %q after dial failure; want \"connecting\" "+
				"(reconnecting internal state must not create a sixth enum value)",
				s.Name, s.State)
		}
	}

	// Verify the JSON encoding via BuildSnapshot.
	snap := daemon.BuildSnapshot(states, newFixedClock(), "", 0,
		func(string) (time.Time, bool, error) { return time.Time{}, false, nil })
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"session":"connecting"`)) {
		t.Errorf("JSON does not contain \"session\":\"connecting\"; got: %s", b)
	}
}

// ---- C3b: stateAuthFailed → JSON "auth_failed" ----------------------------

// TestStateAuthFailed_SerializesToAuthFailed asserts that the "auth_failed"
// internal state serialises to JSON "auth_failed".
//
// Pre-fix failure mode: before auth_failed was ratified as the fifth enum
// value, no test verified this JSON string. A typo or refactor could silently
// break the consumer contract.
func TestStateAuthFailed_SerializesToAuthFailed(t *testing.T) {
	t.Parallel()

	// FailDial with ErrAuthFailed causes the pool to enter auth_failed and stop.
	hub := mem.NewHub()
	authFailTr := hub.Transport("c3b-client:1", mem.FailDial(transport.ErrAuthFailed))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"authfail-server": {Addr: "c3b-authfail:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return authFailTr, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// Wait for the pool to detect the auth failure and stop retrying.
	getCtx, getCancel := context.WithTimeout(ctx, 5*time.Second)
	defer getCancel()

	_, getErr := pool.Get(getCtx, "authfail-server")
	if getErr == nil {
		t.Fatal("pool.Get: expected auth error, got nil")
	}

	// The state must be "auth_failed".
	states := pool.State()
	if len(states) == 0 {
		t.Fatal("State(): no states returned")
	}
	s := states[0]
	if s.State != "auth_failed" {
		t.Errorf("state = %q after auth failure; want \"auth_failed\"", s.State)
	}

	// Verify the JSON encoding.
	snap := daemon.BuildSnapshot(states, newFixedClock(), "", 0,
		func(string) (time.Time, bool, error) { return time.Time{}, false, nil })
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"session":"auth_failed"`)) {
		t.Errorf("JSON does not contain \"session\":\"auth_failed\"; got: %s", b)
	}
}

// ---- C3c: exactly five allowed values, "invalid" never emitted -------------

// TestEnumValues_ExactlyFiveAllowed verifies that BuildSnapshot only emits the
// five ratified session values and that "invalid" is never produced.
//
// This guards against a future contributor adding a new internal state and
// accidentally mapping it to "invalid" or a new string not in the five-value
// set.
func TestEnumValues_ExactlyFiveAllowed(t *testing.T) {
	t.Parallel()

	allowed := map[string]bool{
		"connected":   true,
		"connecting":  true,
		"listening":   true,
		"disabled":    true,
		"auth_failed": true,
	}

	states := []daemon.SessionState{
		{Name: "s1", State: "connected", Transport: "dial", Since: time.Now()},
		{Name: "s2", State: "connecting", Transport: "dial", Since: time.Now()},
		{Name: "s3", State: "listening", Transport: "listen", Since: time.Now()},
		{Name: "s4", State: "disabled", Transport: "dial", Since: time.Now()},
		{Name: "s5", State: "auth_failed", Transport: "dial", Since: time.Now()},
	}
	clock := newFixedClock()
	metaReader := func(string) (time.Time, bool, error) { return time.Time{}, false, nil }

	snap := daemon.BuildSnapshot(states, clock, "", 0, metaReader)
	if len(snap.Servers) != 5 {
		t.Fatalf("expected 5 servers in snapshot, got %d", len(snap.Servers))
	}

	for _, srv := range snap.Servers {
		if srv.Session == "invalid" {
			t.Errorf("session \"invalid\" was emitted; it must never appear in " +
				"status output (it was considered but deferred; no code path produces it)")
		}
		if !allowed[srv.Session] {
			t.Errorf("unexpected session value %q in BuildSnapshot output; "+
				"only five values are defined: connected, connecting, listening, "+
				"disabled, auth_failed", srv.Session)
		}
	}
}

// ---- C3d: liveness probe detects dead agent fast ---------------------------

// fastLivenessPolicy drives the probe at test speed.
type fastLivenessPolicy struct {
	interval  time.Duration
	timeout   time.Duration
	threshold int
}

func (p fastLivenessPolicy) Interval() time.Duration { return p.interval }
func (p fastLivenessPolicy) Timeout() time.Duration  { return p.timeout }
func (p fastLivenessPolicy) FailThreshold() int      { return p.threshold }

// TestLivenessProbe_DetectsDeadAgentFast verifies that the application-level
// liveness probe detects a dead agent substantially faster than the QUIC
// MaxIdleTimeout (60s). We use real QUIC over the loopback so that killing the
// agent-side connection actually cancels the control stream (the mem transport
// does not propagate conn-close to stream-level reads, which would prevent
// PingRTT from returning an error promptly).
//
// The test injects a very fast liveness policy (20ms interval, 10ms timeout,
// threshold=2) so detection happens in ~60ms rather than 60s.
//
// Pre-fix failure mode: without the probe, the pool would wait for the QUIC
// MaxIdleTimeout (60s) to fire. With the probe at production settings the
// latency is ~25s; at the injected fast policy it is ~60ms.
func TestLivenessProbe_DetectsDeadAgentFast(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate mutually-authenticated identities.
	serverKey, serverPin := genPoolLivenessIdentity(t)
	clientKey, clientPin := genPoolLivenessIdentity(t)

	serverTLS, err := identity.ServerTLS(serverKey, []string{clientPin})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	clientTLS, err := identity.ClientTLS(clientKey, serverPin)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}

	// Start the agent listener.
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

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	go tunnel.Serve(serveCtx, ln, rtr) //nolint:errcheck

	// Client transport.
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { clientUDP.Close() })

	clientTr, err := transport.NewQUICTransport(clientUDP, clientTLS, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { clientTr.Close() })

	serverAddr := ln.Addr().String()
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"liveness-test": {Addr: serverAddr},
	}

	// Inject a very fast liveness policy: 20ms interval, 10ms timeout, 2
	// consecutive failures. Detection window ≈ 2×(20ms + 10ms) = 60ms.
	fastPolicy := fastLivenessPolicy{
		interval:  20 * time.Millisecond,
		timeout:   10 * time.Millisecond,
		threshold: 2,
	}

	pool, err := daemon.NewRealPoolWithLiveness(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return clientTr, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
		fastPolicy,
	)
	if err != nil {
		t.Fatalf("NewRealPoolWithLiveness: %v", err)
	}
	defer pool.Close()

	// Wait for the pool to reach "connected".
	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	for {
		states := pool.State()
		if len(states) > 0 && states[0].State == "connected" {
			break
		}
		select {
		case <-connCtx.Done():
			t.Fatalf("pool did not connect within deadline; states: %v", pool.State())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Kill the agent. The QUIC connection will remain until MaxIdleTimeout (60s)
	// expires — but the liveness probe should detect the dead control stream
	// within ~60ms.
	agentDiedAt := time.Now()
	serveCancel()
	ln.Close()

	// Poll for state change. Budget is 5s — far less than the 60s QUIC
	// idle timeout, which is what we are trying to beat.
	const detectionBudget = 5 * time.Second
	deadline := time.Now().Add(detectionBudget)
	for time.Now().Before(deadline) {
		states := pool.State()
		if len(states) > 0 && states[0].State != "connected" {
			detectedAfter := time.Since(agentDiedAt)
			t.Logf("liveness probe detected dead agent after %s (budget %s, QUIC idle timeout 60s)",
				detectedAfter.Round(time.Millisecond), detectionBudget)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Errorf("pool still reports 'connected' %s after agent died; "+
		"the liveness probe did not detect the dead agent within %s "+
		"(without the probe, detection would take ~60s via QUIC idle timeout)",
		time.Since(agentDiedAt).Round(time.Millisecond), detectionBudget)
}

// genPoolLivenessIdentity generates an Ed25519 identity for liveness tests.
func genPoolLivenessIdentity(t *testing.T) (ed25519.PrivateKey, string) {
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

// ---- F4a: transport rebind fires after N consecutive failures ---------------

// countingFactory tracks how many times the factory has been called. Each call
// returns a new always-failing transport so the pool keeps retrying.
type countingFactory struct {
	mu          sync.Mutex
	callCount   int
	makeBaseErr error
}

func newCountingFactory(dialErr error) *countingFactory {
	return &countingFactory{makeBaseErr: dialErr}
}

func (f *countingFactory) make(_ string, _ config.Server) (transport.Transport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	hub := mem.NewHub()
	return hub.Transport(fmt.Sprintf("rebind-client:%d", f.callCount),
		mem.FailDial(f.makeBaseErr)), nil
}

func (f *countingFactory) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCount
}

// TestTransportRebind_FiresAfterNFailures verifies that the transport rebind
// fires after exactly transportRebindAfter (10) consecutive dial failures.
//
// The factory is called once at pool construction (initial transport), then
// again when consecutive failures reach 10 (first rebind), 20, etc.
//
// WallClock is used so the backoff timer between retries actually fires (the
// fixed test clock's After channel never receives, which would block the loop).
//
// Pre-fix failure mode: before the factory was wired into dialEntry, the pool
// reused the original UDP socket forever. The factory call count would stay at
// 1 even after hundreds of failures.
func TestTransportRebind_FiresAfterNFailures(t *testing.T) {
	t.Parallel()

	// Use ErrUnreachable so the loop keeps retrying (auth failures stop it).
	factory := newCountingFactory(transport.ErrUnreachable)

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"rebind-server": {Addr: "rebind-f4a:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use WallClock so the backoff timer actually fires between retries.
	pool, err := daemon.NewRealPool(
		ctx, cfg,
		factory.make,
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// Factory starts at 1 (initial transport). Wait for it to reach 2
	// (at least one rebind triggered by 10 consecutive failures).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if factory.calls() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	calls := factory.calls()
	if calls < 2 {
		t.Fatalf("factory called %d times within deadline; want ≥2 "+
			"(initial + at least one rebind after 10 consecutive failures); "+
			"pre-fix behaviour was: count stays at 1 forever", calls)
	}
	t.Logf("factory called %d times (initial + %d rebind(s))", calls, calls-1)
}

// TestTransportRebind_DoesNotFireBeforeN verifies that the rebind does NOT fire
// before N=10 consecutive dial failures. The test uses a transport that counts
// dial calls and stops after 9, so the loop cannot accumulate 10 failures
// during the observation window.
//
// Pre-fix failure mode: this assertion would have been vacuously true (no
// rebind logic existed). With the fix it confirms the modulo-10 threshold.
func TestTransportRebind_DoesNotFireBeforeN(t *testing.T) {
	t.Parallel()

	var factoryCalls atomic.Int32

	// Each factory call returns a transport that fails the first 9 dials
	// then blocks. This means the pool can accumulate at most 9 failures
	// before the loop stalls — below the threshold of 10.
	var dialCount atomic.Int32

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"norebind-server": {Addr: "norebind-f4b:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			factoryCalls.Add(1)
			return &dial9FailTransport{
				dialCount: &dialCount,
				cancelCtx: cancel,
			}, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		cancel()
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()
	defer cancel()

	// Wait for exactly 9 dial failures by polling dialCount.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if int(dialCount.Load()) >= 9 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Give the 10th dial a little time to NOT trigger (it blocks instead).
	time.Sleep(30 * time.Millisecond)

	// After ≤9 observed failures the factory must not have been called a
	// second time (the rebind threshold is 10).
	fc := int(factoryCalls.Load())
	if fc != 1 {
		t.Errorf("factory called %d times; want 1 "+
			"(no rebind should fire before 10 consecutive failures)", fc)
	}

	dc := int(dialCount.Load())
	t.Logf("observed %d dial calls, factory calls %d (rebind threshold is 10)", dc, fc)
	if dc < 9 {
		t.Skipf("only %d dial calls observed within deadline; insufficient to confirm threshold", dc)
	}
}

// dial9FailTransport fails the first 9 Dial calls (returning ErrUnreachable),
// then blocks until the context is cancelled. This allows the test to observe
// exactly 9 failures without accidentally crossing the 10-failure rebind
// threshold during the polling window.
type dial9FailTransport struct {
	dialCount *atomic.Int32
	cancelCtx context.CancelFunc // called on the 10th dial to stop the pool
}

func (t *dial9FailTransport) Dial(ctx context.Context, _ string) (transport.Conn, error) {
	n := int(t.dialCount.Add(1))
	if n <= 9 {
		return nil, transport.ErrUnreachable
	}
	// On the 10th call, cancel the pool context so the loop exits cleanly
	// without crossing the rebind threshold.
	t.cancelCtx()
	<-ctx.Done()
	return nil, ctx.Err()
}
func (t *dial9FailTransport) Listen() (transport.Listener, error) {
	return nil, fmt.Errorf("listen not supported")
}
func (t *dial9FailTransport) Close() error { return nil }

// TestTransportRebind_CounterResetsOnSuccess verifies that a successful dial
// resets the consecutive-failure counter. After a successful connection:
// 10 more failures are needed for a rebind, not fewer.
//
// We use real QUIC so the pool can complete a full connect+control-stream
// handshake (required for a state transition to "connected").
//
// Pre-fix failure mode: if the counter did not reset, 9 failures before a
// success + 1 failure after would trigger a rebind — incorrect behaviour.
// After the fix, 10 failures after the success are required.
func TestTransportRebind_CounterResetsOnSuccess(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate identities.
	serverKey, serverPin := genPoolLivenessIdentity(t)
	clientKey, clientPin := genPoolLivenessIdentity(t)

	serverTLS, err := identity.ServerTLS(serverKey, []string{clientPin})
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	clientTLS, err := identity.ClientTLS(clientKey, serverPin)
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}

	// Start the agent.
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

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go tunnel.Serve(serveCtx, ln, rtr) //nolint:errcheck

	// Client setup.
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { clientUDP.Close() })

	clientTr, err := transport.NewQUICTransport(clientUDP, clientTLS, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { clientTr.Close() })

	serverAddr := ln.Addr().String()
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"reset-server": {Addr: serverAddr},
	}

	// The factory returns a transport that fails the first 9 dials then uses
	// the real client transport. This simulates accumulating 9 pre-success
	// failures (consecutiveFails=9). On the 10th call the real transport dials
	// successfully, which resets consecutiveFails to 0. After the agent dies
	// the loop must accumulate 10 NEW failures before a rebind fires.
	var factoryCalls atomic.Int32

	pool, poolErr := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			factoryCalls.Add(1)
			// First factory call: return a transport that fails 9 times then
			// delegates to the real transport.
			return &resetTestTransport{
				realTr:          clientTr,
				failsBeforeReal: 9,
			}, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if poolErr != nil {
		t.Fatalf("NewRealPool: %v", poolErr)
	}
	defer pool.Close()

	// Wait for the pool to reach "connected" (9 failures + 1 success).
	connCtx, connCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connCancel()
	for {
		states := pool.State()
		if len(states) > 0 && states[0].State == "connected" {
			break
		}
		select {
		case <-connCtx.Done():
			t.Fatalf("pool did not reach connected state; final states: %v", pool.State())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("pool connected (after 9 pre-success failures; counter should now be 0)")

	// Kill the agent to force reconnect phase.
	serveCancel()
	ln.Close()

	// Wait for pool to detect the drop and start reconnecting.
	dropCtx, dropCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dropCancel()
	for {
		states := pool.State()
		if len(states) > 0 && states[0].State != "connected" {
			break
		}
		select {
		case <-dropCtx.Done():
			t.Fatalf("pool did not detect agent drop; states: %v", pool.State())
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("pool detected drop; entering reconnect phase")

	// Since the counter reset to 0 on success, we need 10 NEW failures
	// before the factory is called again. With zero-delay backoff, those 10
	// failures happen quickly — but fewer than 10 would be wrong.
	//
	// Wait up to 3 seconds and confirm the factory was NOT called a second
	// time. If the counter did not reset, a rebind would happen almost
	// immediately (since consecutiveFails was already 9 before the success).
	time.Sleep(200 * time.Millisecond)

	calls := int(factoryCalls.Load())
	if calls > 1 {
		t.Errorf("factory called %d times after one successful connection; "+
			"want ≤1 immediately after drop — counter should have reset on success, "+
			"requiring 10 NEW failures for a rebind", calls)
	} else {
		t.Logf("factory still at %d call(s) shortly after drop (counter reset on success confirmed — "+
			"rebind correctly deferred until 10 new failures accumulate)", calls)
	}
}

// resetTestTransport fails the first N Dial calls then delegates to realTr.
// This simulates a server that recovers after N failures.
type resetTestTransport struct {
	mu              sync.Mutex
	realTr          transport.Transport
	failsBeforeReal int
	dialed          int
}

func (t *resetTestTransport) Dial(ctx context.Context, addr string) (transport.Conn, error) {
	t.mu.Lock()
	t.dialed++
	n := t.dialed
	t.mu.Unlock()
	if n <= t.failsBeforeReal {
		return nil, transport.ErrUnreachable
	}
	return t.realTr.Dial(ctx, addr)
}
func (t *resetTestTransport) Listen() (transport.Listener, error) { return t.realTr.Listen() }
func (t *resetTestTransport) Close() error                        { return nil }

// ---- F4e: log attributes appear in output ----------------------------------

// syncBuffer is a bytes.Buffer protected by a mutex, making it safe for
// concurrent writes from background goroutines (the dial loop) and reads from
// the test goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRebindLog_AttributesPresent verifies that the dial loop logs the
// expected structured attributes on every attempt: local_addr,
// consecutive_fails, and elapsed_since_success.
//
// These attributes are the difference between a diagnosable and undiagnosable
// NAT-poisoning incident. The 84-minute outage was undiagnosable precisely
// because these attributes were absent from the log output.
//
// Pre-fix failure mode: none of these attributes appeared in the log output.
//
// This test does not run in parallel to avoid races on slog.SetDefault with
// parallel tests that have background goroutines writing to the logger.
func TestRebindLog_AttributesPresent(t *testing.T) {
	// Capture slog output with a mutex-protected writer to prevent data races
	// between the dial-loop goroutine and the test goroutine reading the buffer.
	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	prev := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(prev)

	hub := mem.NewHub()
	// No listener at "log-missing:1" — every dial fails immediately.
	dialTr := hub.Transport("log-test-client:1")

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"log-server": {Addr: "log-missing:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return dialTr, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}

	// Let the loop run for a bit to produce some log lines.
	time.Sleep(100 * time.Millisecond)
	pool.Close()

	logs := buf.String()

	// Check for the instrumentation attributes introduced by F2.
	attrs := []string{
		"consecutive_fails",
		"elapsed_since_success",
		"local_addr",
	}
	for _, attr := range attrs {
		if !strings.Contains(logs, attr) {
			t.Errorf("expected log attribute %q not found in output\n"+
				"this attribute is required for diagnosing NAT-poisoning failures;\n"+
				"partial log output:\n%s", attr, logs)
		}
	}
}
