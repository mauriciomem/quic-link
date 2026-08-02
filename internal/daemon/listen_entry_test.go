package daemon_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// A server this machine waits for behaves like a dialed one from the outside:
// Get blocks until a session exists, State reports honestly, Close tears down.
// What differs is that recovery is the peer's job, so the loop waits rather
// than retries, and that a second authenticated peer can take over.

// reverseRig builds a pool holding exactly one waiting server, plus the pieces
// an agent needs to connect into it.
type reverseRig struct {
	pool     daemon.SessionPool
	hub      *mem.Hub
	agentT   func() transport.Transport // a fresh agent-side transport per dial
	listenAt string
	cancel   context.CancelFunc
}

func newReverseRig(t *testing.T) *reverseRig {
	t.Helper()
	return newReverseRigWithClock(t, daemon.WallClock{})
}

// newReverseRigWithClock builds the same rig with an injected clock, so a
// test can move time instead of waiting for it.
func newReverseRigWithClock(t *testing.T, clock daemon.Clock) *reverseRig {
	t.Helper()

	hub := mem.NewHub()
	daemonLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	const listenAt = "reverse-daemon:1"
	// The daemon's transport listens; the agent dials into it.
	daemonT := hub.Transport(listenAt, mem.WithCert(daemonLeaf))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"rev": {Listen: listenAt},
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return daemonT, nil },
		daemon.DefaultReconnectPolicy(),
		clock,
		nil,
	)
	if err != nil {
		cancel()
		t.Fatalf("NewRealPool: %v", err)
	}
	t.Cleanup(func() { pool.Close(); cancel() })

	n := 0
	agentT := func() transport.Transport {
		n++
		leaf, _, ierr := mem.NewIdentity()
		if ierr != nil {
			t.Fatalf("NewIdentity: %v", ierr)
		}
		return hub.Transport("reverse-agent:"+string(rune('a'+n)), mem.WithCert(leaf))
	}

	return &reverseRig{pool: pool, hub: hub, agentT: agentT, listenAt: listenAt, cancel: cancel}
}

// connectAgent dials into the waiting daemon and serves the connection the way
// a real agent does, so the daemon's control stream can actually open.
func (r *reverseRig) connectAgent(t *testing.T, ctx context.Context) transport.Conn {
	t.Helper()
	conn, err := r.agentT().Dial(ctx, r.listenAt)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go tunnel.ServeConn(ctx, conn, rtr)
	return conn
}

// connectHalfOpenAgent dials in and completes the handshake but never serves
// anything, so the daemon's control-stream open cannot succeed.
func (r *reverseRig) connectHalfOpenAgent(t *testing.T, ctx context.Context) transport.Conn {
	t.Helper()
	conn, err := r.agentT().Dial(ctx, r.listenAt)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	return conn
}

// TestListenEntry_InitialState_Listening: before any peer, the server reports
// that it is waiting, in the direction it was configured for.
func TestListenEntry_InitialState_Listening(t *testing.T) {
	r := newReverseRig(t)

	states := r.pool.State()
	if len(states) != 1 {
		t.Fatalf("State() returned %d entries, want 1", len(states))
	}
	if states[0].State != "listening" {
		t.Errorf("State = %q, want listening", states[0].State)
	}
	if states[0].Transport != "listen" {
		t.Errorf("Transport = %q, want listen", states[0].Transport)
	}
}

// TestListenEntry_Get_BlocksUntilPeerConnects: Get waits for a peer rather than
// failing immediately, which is what makes an attach arriving before the agent
// does behave the same way it does in the other direction.
func TestListenEntry_Get_BlocksUntilPeerConnects(t *testing.T) {
	r := newReverseRig(t)

	short, cancelShort := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelShort()
	if _, err := r.pool.Get(short, "rev"); err == nil {
		t.Fatal("Get returned a connection before any peer connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	got := make(chan error, 1)
	go func() {
		_, err := r.pool.Get(ctx, "rev")
		got <- err
	}()

	r.connectAgent(t, ctx)

	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Get after peer connected: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Get did not unblock after a peer connected")
	}

	waitForPoolState(t, r.pool, "rev", "connected", 5*time.Second)
}

// TestListenEntry_AcceptsAgainAfterDrop: the loop keeps accepting. Recovery in
// this direction is the agent reconnecting, so a one-shot accept would strand
// the server after its first peer ever left.
func TestListenEntry_AcceptsAgainAfterDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newReverseRig(t)

	first := r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)

	if err := first.CloseWithError(0, "test-forced drop"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}
	waitForPoolState(t, r.pool, "rev", "listening", 10*time.Second)

	r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)
}

// TestListenEntry_HalfOpenPeerDoesNotEvictHealthySession is the important one.
// A peer that completes its handshake and then goes quiet must not displace a
// session that is currently working: it has proved only that it holds the key,
// not that it can carry traffic.
func TestListenEntry_HalfOpenPeerDoesNotEvictHealthySession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	r := newReverseRig(t)

	healthy := r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)

	incumbent, err := r.pool.Get(ctx, "rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// A peer that authenticates and then stalls.
	r.connectHalfOpenAgent(t, ctx)

	// The incumbent must survive the newcomer's whole control-open timeout and
	// stay the connection Get hands out.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		state, _ := r.pool.EntryState("rev")
		if state != "connected" {
			t.Fatalf("healthy session left the connected state (%q) while a half-open peer was pending", state)
		}
		current, gerr := r.pool.Get(ctx, "rev")
		if gerr != nil {
			t.Fatalf("Get while a half-open peer was pending: %v", gerr)
		}
		if current != incumbent {
			t.Fatal("a peer that never opened a control stream displaced the working session")
		}
		time.Sleep(100 * time.Millisecond)
	}

	if healthy.Context().Err() != nil {
		t.Fatal("the healthy connection was torn down by a half-open newcomer")
	}
}

// TestListenEntry_NewerAuthenticatedPeerReplacesIncumbent: an agent that has
// genuinely reconnected takes over, so a stale session cannot lock it out.
func TestListenEntry_NewerAuthenticatedPeerReplacesIncumbent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	r := newReverseRig(t)

	first := r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)
	incumbent, err := r.pool.Get(ctx, "rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	r.connectAgent(t, ctx)

	replacement := waitForDistinctConn(t, ctx, r.pool, "rev", incumbent, 15*time.Second)
	if replacement == nil {
		t.Fatal("no replacement connection after a newer authenticated peer connected")
	}

	// The displaced connection must actually be torn down, not merely dropped
	// from the map, or the old agent would sit there believing it is connected.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if first.Context().Err() != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the displaced connection was never closed")
}

// TestListenEntry_ReplacementLogNeverCarriesAFullPin: the replacement event is
// exactly where an operator looks after an unexpected takeover, and it is a new
// log site, which is where a full key fingerprint has leaked before.
func TestListenEntry_ReplacementLogNeverCarriesAFullPin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	buf := captureLogs(t)
	r := newReverseRig(t)

	r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)
	incumbent, err := r.pool.Get(ctx, "rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	r.connectAgent(t, ctx)
	if got := waitForDistinctConn(t, ctx, r.pool, "rev", incumbent, 15*time.Second); got == nil {
		t.Fatal("replacement never happened")
	}

	out := buf.String()
	if !strings.Contains(out, "session replaced") {
		t.Errorf("no replacement event logged; got:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		for _, field := range strings.Fields(line) {
			// A pin is 44 base64 characters. Anything that long in a log line
			// is the thing we promised never to print.
			if len(strings.Trim(field, `"peer=`)) >= 44 {
				t.Errorf("log line looks like it carries a full pin: %q", line)
			}
		}
	}
}

// TestListenEntry_CloseReleasesTheSocket: the address must be reusable after
// shutdown, and Close must not hang waiting on the accept loop.
func TestListenEntry_CloseReleasesTheSocket(t *testing.T) {
	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	const at = "reverse-close:1"

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"rev": {Listen: at}}

	build := func() daemon.SessionPool {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		pool, perr := daemon.NewRealPool(
			ctx, cfg,
			func(_ string, _ config.Server) (transport.Transport, error) {
				return hub.Transport(at, mem.WithCert(leaf)), nil
			},
			daemon.DefaultReconnectPolicy(), daemon.WallClock{}, nil,
		)
		if perr != nil {
			t.Fatalf("NewRealPool: %v", perr)
		}
		return pool
	}

	first := build()
	done := make(chan struct{})
	go func() { first.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung; the accept loop was never released")
	}

	// Binding the same address again proves the socket really went away.
	second := build()
	second.Close()
}

// TestPool_MixedDialAndListenServers: a config holding both kinds must build
// both kinds. A waiting server that fell through to the dialing path would be
// built with no address at all and would retry nothing, forever.
func TestPool_MixedDialAndListenServers(t *testing.T) {
	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"fwd": {Addr: "mixed-agent:1"},
		"rev": {Listen: "mixed-daemon:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(name string, srv config.Server) (transport.Transport, error) {
			if srv.Listen != "" {
				return hub.Transport(srv.Listen, mem.WithCert(leaf)), nil
			}
			return hub.Transport("mixed-client:1", mem.WithCert(leaf)), nil
		},
		daemon.DefaultReconnectPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	byName := map[string]daemon.SessionState{}
	for _, s := range pool.State() {
		byName[s.Name] = s
	}
	if got := byName["fwd"].Transport; got != "dial" {
		t.Errorf("fwd Transport = %q, want dial", got)
	}
	if got := byName["rev"].Transport; got != "listen" {
		t.Errorf("rev Transport = %q, want listen", got)
	}
	if got := byName["rev"].State; got != "listening" {
		t.Errorf("rev State = %q, want listening", got)
	}
}

// captureLogs redirects the default logger into a race-safe buffer for the
// duration of a test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}
