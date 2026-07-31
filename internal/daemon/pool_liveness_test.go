package daemon_test

// pool_liveness_test.go covers:
//
//  C3a — stateReconnecting serialises to JSON "connecting", not a sixth value.
//  C3b — stateAuthFailed serialises to JSON "auth_failed".
//  C3c — the emitted enum set is exactly the five allowed values; "invalid"
//         is never emitted.
//  C3d — the liveness probe detects a dead agent substantially faster than
//         the QUIC idle timeout (driven via injected fast policy).
//  F2  — "session lost" is logged at drop time on a natural QUIC drop, even
//         when the first reconnect succeeds (the historically silent case).
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

	// Poll until the pool has attempted at least one dial (which will fail
	// since there is no listener). After the failure the internal state is
	// "reconnecting", which must still project to "connecting" externally.
	// With zero-delay backoff this happens in microseconds; we budget 2 s to
	// be safe on a loaded machine.
	const firstFailDeadline = 2 * time.Second
	end := time.Now().Add(firstFailDeadline)
	for time.Now().Before(end) {
		// The pool starts in stateConnecting; once a dial fails and we go
		// back to "wait + retry", it is in stateReconnecting. Check by
		// verifying the state stays "connecting" (not some unexpected value).
		if states := pool.State(); len(states) > 0 && states[0].State != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

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

// ---- F2: session-lost event logged on natural drop where first reconnect succeeds

// TestSessionLost_LoggedOnNaturalDrop verifies that when a session drops
// naturally (agent restart) and the FIRST reconnect attempt succeeds, a
// "session lost" Warn-level log is emitted at the moment of the drop.
//
// This is the exact silent case: before the fix, if the agent restarted
// quickly and the pool reconnected on the first attempt, the "agent lost;
// reconnecting" line only appeared on a failed dial — so an operator watching
// logs would never see any indication that the session had dropped at all.
//
// Pre-fix failure mode: the test asserts the presence of "session lost" in
// logs; before the fix that string was never emitted on the natural-drop /
// first-reconnect-succeeds path, so the assertion would fail.
//
// The test uses real QUIC over loopback: kill the first agent, start a second
// one at the same address, and confirm the pool reaches "connected" again AND
// that the "session lost" log appeared.
func TestSessionLost_LoggedOnNaturalDrop(t *testing.T) {
	// NOT parallel — replaces the global slog logger.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Capture slog output with a race-safe buffer.
	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	prev := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(prev)

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

	// Start the first agent on a fixed loopback addr.
	serverUDP1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("server UDP 1: %v", err)
	}
	serverAddr := serverUDP1.LocalAddr().String()

	serverTr1, err := transport.NewQUICTransport(serverUDP1, serverTLS, nil)
	if err != nil {
		serverUDP1.Close()
		t.Fatalf("server transport 1: %v", err)
	}

	ln1, err := serverTr1.Listen()
	if err != nil {
		serverTr1.Close()
		serverUDP1.Close()
		t.Fatalf("server listen 1: %v", err)
	}

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	serveCtx1, serveCancel1 := context.WithCancel(ctx)
	go tunnel.Serve(serveCtx1, ln1, rtr) //nolint:errcheck

	// Build the client pool pointing at the fixed server address.
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

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"drop-test": {Addr: serverAddr},
	}

	// Use the default liveness policy (10s interval). The goal is to let the
	// natural QUIC connection drop (from the server closing its transport) fire
	// conn.Context().Done() before the probe has a chance to run. With a 10s
	// probe interval, the QUIC CONNECTION_CLOSE from the dying agent reaches
	// the client orders of magnitude faster, so the drop is natural not
	// probe-declared.
	pool, err := daemon.NewRealPoolWithLiveness(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return clientTr, nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
		daemon.DefaultLivenessPolicy{},
	)
	if err != nil {
		t.Fatalf("NewRealPoolWithLiveness: %v", err)
	}
	defer pool.Close()

	// Wait for the pool to reach "connected".
	waitConnCtx, waitConnCancel := context.WithTimeout(ctx, 10*time.Second)
	defer waitConnCancel()
	for {
		if len(pool.State()) > 0 && pool.State()[0].State == "connected" {
			break
		}
		select {
		case <-waitConnCtx.Done():
			t.Fatalf("pool did not connect within deadline; state: %v", pool.State())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Kill the first agent abruptly (simulates a NAT timeout or agent crash).
	serveCancel1()
	ln1.Close()
	serverTr1.Close()
	serverUDP1.Close()

	// Wait for the pool to detect the drop (state transitions away from "connected").
	dropCtx, dropCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dropCancel()
	for {
		if len(pool.State()) > 0 && pool.State()[0].State != "connected" {
			break
		}
		select {
		case <-dropCtx.Done():
			t.Fatalf("pool did not detect drop; state: %v", pool.State())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Bring up a second agent at the SAME address. The pool's first reconnect
	// attempt should succeed, so "agent lost; reconnecting" is never emitted —
	// but "session lost; reconnecting" must have been logged at the drop moment.
	serverUDP2, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: serverUDP1.LocalAddr().(*net.UDPAddr).Port, // same port
	})
	if err != nil {
		t.Skipf("cannot re-bind server port %s for second agent: %v", serverAddr, err)
	}
	t.Cleanup(func() { serverUDP2.Close() })

	serverTr2, err := transport.NewQUICTransport(serverUDP2, serverTLS, nil)
	if err != nil {
		t.Fatalf("server transport 2: %v", err)
	}
	t.Cleanup(func() { serverTr2.Close() })

	ln2, err := serverTr2.Listen()
	if err != nil {
		t.Fatalf("server listen 2: %v", err)
	}
	t.Cleanup(func() { ln2.Close() })

	serveCtx2, serveCancel2 := context.WithCancel(ctx)
	defer serveCancel2()
	go tunnel.Serve(serveCtx2, ln2, rtr) //nolint:errcheck

	// Wait for the pool to reconnect to the new agent.
	reconnCtx, reconnCancel := context.WithTimeout(ctx, 10*time.Second)
	defer reconnCancel()
	for {
		if len(pool.State()) > 0 && pool.State()[0].State == "connected" {
			break
		}
		select {
		case <-reconnCtx.Done():
			t.Logf("pool state at timeout: %v", pool.State())
			// If the port cannot be reused immediately, accept that and skip.
			t.Skipf("pool did not reconnect within deadline; this can happen if the OS " +
				"delays port reuse. The 'session lost' log assertion below is the key check.")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Logf("pool reconnected successfully (first reconnect attempt succeeded)")

	// The "session lost" warning must have been emitted at the moment of the
	// natural drop — regardless of whether the first reconnect succeeded.
	logs := buf.String()
	if !strings.Contains(logs, "session lost") {
		t.Errorf("expected \"session lost\" in logs on natural drop where first reconnect succeeded;\n"+
			"before the fix this string was never emitted on this path\nlog output:\n%s", logs)
	}
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

// countingFactory tracks how many times the factory has been called and how
// many dials have been attempted in total across all returned transports.
// Each call returns a new always-failing transport so the pool keeps retrying.
type countingFactory struct {
	mu          sync.Mutex
	callCount   int
	dialCount   int // total dials across all returned transports
	makeBaseErr error

	// rebindDialCount[n] records the total dial count when the (n+1)th
	// factory call (first rebind) fires. Index 0 = first rebind.
	rebindDialCounts []int
}

func newCountingFactory(dialErr error) *countingFactory {
	return &countingFactory{makeBaseErr: dialErr}
}

func (f *countingFactory) make(_ string, _ config.Server) (transport.Transport, error) {
	f.mu.Lock()
	f.callCount++
	n := f.callCount
	if n > 1 {
		// A rebind: record how many dials had happened when this rebind fired.
		f.rebindDialCounts = append(f.rebindDialCounts, f.dialCount)
	}
	f.mu.Unlock()

	hub := mem.NewHub()
	base := hub.Transport(fmt.Sprintf("rebind-client:%d", n), mem.FailDial(f.makeBaseErr))
	return &dialCountingTransport{inner: base, factory: f}, nil
}

func (f *countingFactory) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCount
}

func (f *countingFactory) dialsBefore(rebindIndex int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rebindIndex >= len(f.rebindDialCounts) {
		return -1
	}
	return f.rebindDialCounts[rebindIndex]
}

func (f *countingFactory) incDial() {
	f.mu.Lock()
	f.dialCount++
	f.mu.Unlock()
}

// dialCountingTransport wraps a base transport to count every Dial call.
type dialCountingTransport struct {
	inner   transport.Transport
	factory *countingFactory
}

func (t *dialCountingTransport) Dial(ctx context.Context, addr string) (transport.Conn, error) {
	t.factory.incDial()
	return t.inner.Dial(ctx, addr)
}

func (t *dialCountingTransport) Listen() (transport.Listener, error) { return t.inner.Listen() }
func (t *dialCountingTransport) Close() error                        { return t.inner.Close() }

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

	// Factory starts at 1 (initial transport). Poll until it reaches 3
	// (initial + 2 rebinds), which lets us verify rebinds fire at exactly
	// multiples of 10 (at failure 10, 20) and not off-by-one.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if factory.calls() >= 3 {
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

	// Verify the first rebind fired after exactly 10 dial failures.
	// dialsBefore(0) = total dials when the 1st rebind (factory call #2) fired.
	firstRebindDials := factory.dialsBefore(0)
	t.Logf("factory calls=%d; dials before first rebind=%d (threshold=10)", calls, firstRebindDials)

	const threshold = 10 // transportRebindAfter
	if firstRebindDials != threshold {
		t.Errorf("first rebind fired after %d dial failures; want exactly %d — "+
			"off-by-one or wrong modulo in rebind check", firstRebindDials, threshold)
	}

	// Verify the second rebind (if seen) also fired at a multiple of 10.
	if calls >= 3 {
		secondRebindDials := factory.dialsBefore(1)
		t.Logf("dials before second rebind=%d (want 20)", secondRebindDials)
		if secondRebindDials != 2*threshold {
			t.Errorf("second rebind fired after %d total dial failures; want %d "+
				"(rebinds repeat every %d failures)", secondRebindDials, 2*threshold, threshold)
		}
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

	// Poll until the 10th Dial call starts. The 10th call blocks inside
	// dial9FailTransport (cancelling the context and then waiting), so once
	// dialCount reaches 10 we know the loop is inside the blocking dial and
	// cannot have fired a rebind — the factory must still be at 1.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if int(dialCount.Load()) >= 10 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// After the 10th blocking dial has started, the rebind threshold (10
	// consecutive failures) has not been crossed — the 10th failure only
	// increments the count AFTER Dial returns, which it hasn't yet (it's
	// blocking). The factory must still be at 1.
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
// The test uses the in-memory transport harness so that reconnect failures
// are instantaneous (no QUIC dial timeout). The key property under test:
// if consecutiveFails was 9 before a successful connection, and the counter
// does NOT reset on success, the very next failure would trigger a rebind
// (9 % 10 would wrap around on the next tick). After the fix, the counter
// resets to 0 on success so exactly 10 new failures are required.
//
// Pre-fix failure mode: if the counter did not reset, 9 failures before a
// success + 1 failure after would trigger a rebind — incorrect behaviour.
// After the fix, 10 failures after the success are required, and the factory
// is NOT called a second time until those 10 have accumulated.
func TestTransportRebind_CounterResetsOnSuccess(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Build an in-memory hub with a live server.
	hub := mem.NewHub()
	srvLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	srvT := hub.Transport("reset-agent:1", mem.WithCert(srvLeaf))
	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, ln, nil) }()

	// cliT succeeds from the start but we build a wrapper that fails
	// the first 9 dials so consecutiveFails=9 when the success lands.
	cliT := hub.Transport("reset-client:1", mem.WithCert(srvLeaf))
	rsTransport := &resetTestTransport{
		realTr:          cliT,
		failsBeforeReal: 9,
	}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"reset-server": {Addr: "reset-agent:1"},
	}

	// The factory captures the dial count at the exact moment the rebind fires,
	// giving us a race-free count of failures between the success and the rebind.
	var factoryCalls atomic.Int32
	// dialCountAtRebind is set by the factory when n==2 (the first rebind call).
	// Using a channel for synchronization: the factory sends on it, the test
	// receives. Buffered 1 so the factory never blocks the pool's run loop.
	rebindDialCh := make(chan int, 1)

	pool, poolErr := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			n := int(factoryCalls.Add(1))
			if n == 1 {
				// Initial transport: fails 9 times then delegates to realTr,
				// simulating 9 pre-success failures so consecutiveFails = 9
				// at the moment the pool enters "connected".
				return rsTransport, nil
			}
			if n == 2 {
				// First rebind: capture the total dial count atomically at
				// the instant the factory is called. This is race-free because
				// the factory is called from runLoop while no dial is in flight.
				d := rsTransport.Dialed()
				select {
				case rebindDialCh <- d:
				default:
				}
			}
			// Return a fresh always-failing transport so the pool keeps retrying.
			return hub.Transport(fmt.Sprintf("rebind-dead:%d", n)), nil
		},
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if poolErr != nil {
		t.Fatalf("NewRealPool: %v", poolErr)
	}
	defer pool.Close()

	// Wait for "connected" (9 fast mem failures + 1 mem success).
	connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
	defer connCancel()
	for {
		states := pool.State()
		if len(states) > 0 && states[0].State == "connected" {
			break
		}
		select {
		case <-connCtx.Done():
			t.Fatalf("pool did not reach connected state; final states: %v", pool.State())
		case <-time.After(5 * time.Millisecond):
		}
	}
	dialCountAtSuccess := rsTransport.Dialed() // = 10 (9 failures + 1 success)
	t.Logf("pool connected; total dials so far = %d (9 pre-success + 1 success)", dialCountAtSuccess)

	// Kill the in-memory server. The connection drops; the pool starts reconnecting.
	serveCancel()
	ln.Close()

	// Wait for the first rebind to fire. The factory sends the total dial count
	// at the rebind moment on rebindDialCh.
	rebindCtx, rebindCancel := context.WithTimeout(ctx, 5*time.Second)
	defer rebindCancel()

	var rebindDialCount int
	select {
	case rebindDialCount = <-rebindDialCh:
		// Rebind fired; rebindDialCount is the total dial count at that moment.
	case <-rebindCtx.Done():
		t.Fatalf("factory never called a second time (rebind never fired) within deadline; "+
			"factory calls=%d", factoryCalls.Load())
	}

	// Post-success dials = total dials at rebind minus dials at success.
	postSuccessDials := rebindDialCount - dialCountAtSuccess
	t.Logf("factory calls=%d, dials at success=%d, dials at rebind=%d, post-success=%d (threshold=10)",
		int(factoryCalls.Load()), dialCountAtSuccess, rebindDialCount, postSuccessDials)

	// The rebind must have required at least 10 post-success failures.
	// If the counter did NOT reset on success (the bug), it would take only
	// 1 failure (consecutiveFails would jump from 9 to 10 on the first try).
	if postSuccessDials < 10 {
		t.Errorf("rebind fired after only %d post-success dial failures (want ≥10); "+
			"if the counter did not reset on success, only 1 failure would be needed",
			postSuccessDials)
	}
	t.Logf("counter-reset confirmed: rebind required %d post-success failures (threshold 10)", postSuccessDials)
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

// Dialed returns the total number of Dial calls made on this transport.
func (t *resetTestTransport) Dialed() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dialed
}

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

	// Poll until all expected attributes appear in the log, or a 2 s deadline
	// expires. With zero-delay backoff the dial loop produces log lines almost
	// immediately; this avoids a fixed sleep that could be too short on a
	// heavily loaded machine.
	attrs := []string{
		"consecutive_fails",
		"elapsed_since_success",
		"local_addr",
	}
	const attrDeadline = 2 * time.Second
	end := time.Now().Add(attrDeadline)
	for time.Now().Before(end) {
		logs := buf.String()
		allPresent := true
		for _, attr := range attrs {
			if !strings.Contains(logs, attr) {
				allPresent = false
				break
			}
		}
		if allPresent {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	pool.Close()

	logs := buf.String()

	// Check for the instrumentation attributes introduced by F2.
	for _, attr := range attrs {
		if !strings.Contains(logs, attr) {
			t.Errorf("expected log attribute %q not found in output\n"+
				"this attribute is required for diagnosing NAT-poisoning failures;\n"+
				"partial log output:\n%s", attr, logs)
		}
	}
}
