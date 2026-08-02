package daemon_test

// A laptop that sleeps overnight does not experience time passing; it
// experiences a discontinuity. Wall-clock readings jump by hours between two
// consecutive statements, and timers armed before the suspend come due all at
// once. These tests stand in for that, deterministically and on demand, by
// driving the daemon's clock seam directly.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- a clock the test drives ------------------------------------------------

// jumpClock is a Clock whose time only moves when a test moves it. Timers
// handed out by After are held until an Advance carries the clock past their
// deadline, at which point they all fire.
//
// This is deliberately not the existing fixedClock: that one hands out a
// channel nothing ever writes to, which is fine for reading a status snapshot
// but makes any code that waits on a timer block forever. Everything that
// needed a timer to fire has so far used the real wall clock, which cannot be
// jumped.
//
// No goroutines are involved. Timer channels are buffered, so firing one never
// blocks and an unfired timer holds nothing open.
type jumpClock struct {
	mu      sync.Mutex
	now     time.Time
	pending []*jumpTimer
	// armed counts every After call ever made, so a test can wait for the
	// code under test to actually reach its wait point instead of guessing.
	armed int
}

type jumpTimer struct {
	deadline time.Time
	ch       chan time.Time
}

func newJumpClock() *jumpClock {
	return &jumpClock{now: time.Date(2026, 8, 2, 23, 0, 0, 0, time.UTC)}
}

func (c *jumpClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *jumpClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

func (c *jumpClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed++
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.pending = append(c.pending, &jumpTimer{deadline: c.now.Add(d), ch: ch})
	return ch
}

// Advance moves the clock forward and fires every timer the jump has carried
// past its deadline. A multi-hour jump therefore delivers every outstanding
// timer at once, which is exactly what a resuming machine sees.
func (c *jumpClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.pending[:0]
	for _, tm := range c.pending {
		if tm.deadline.After(c.now) {
			kept = append(kept, tm)
			continue
		}
		tm.ch <- c.now
	}
	c.pending = kept
}

// armCount reports how many timers have been requested over the clock's life.
func (c *jumpClock) armCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.armed
}

// waitForArms blocks until at least n timers have ever been requested, so a
// test can synchronise on the loop reaching its wait point rather than sleeping
// a guessed interval.
func (c *jumpClock) waitForArms(t *testing.T, n int, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if c.armCount() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("clock: only %d timer(s) armed within %s, want at least %d — "+
		"the loop never reached its wait point", c.armCount(), budget, n)
}

// ---- a dial counter ---------------------------------------------------------

// countingDeadTransport dials an address with no listener and counts attempts.
type countingDeadTransport struct {
	inner transport.Transport
	mu    sync.Mutex
	dials int
}

func (t *countingDeadTransport) Dial(ctx context.Context, addr string) (transport.Conn, error) {
	t.mu.Lock()
	t.dials++
	t.mu.Unlock()
	return t.inner.Dial(ctx, addr)
}

func (t *countingDeadTransport) Listen() (transport.Listener, error) { return t.inner.Listen() }
func (t *countingDeadTransport) Close() error                        { return t.inner.Close() }

func (t *countingDeadTransport) dialCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dials
}

// waitForDials polls until the transport has recorded at least n dials.
func waitForDials(t *testing.T, tr *countingDeadTransport, n int, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if tr.dialCount() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d dial(s) observed within %s, want at least %d — "+
		"the reconnect loop is wedged", tr.dialCount(), budget, n)
}

// ceilingPolicy is the production schedule with the jitter draw pinned to its
// maximum, so a test gets the full, deterministic backoff interval rather than
// a random one. The point here is the clock jump, not the draw.
func ceilingPolicy() daemon.ExponentialReconnectPolicy {
	return daemon.ExponentialReconnectPolicy{
		Base:         250 * time.Millisecond,
		Factor:       2,
		Cap:          15 * time.Second,
		StableAfter_: 60 * time.Second,
		Rand:         func() float64 { return 1.0 },
	}
}

// ---- the tests --------------------------------------------------------------

// TestReconnect_MultiHourClockJumpMidBackoff is the overnight-suspend stand-in.
// The daemon is mid-backoff against an agent that is not there when the clock
// jumps six hours. Three things must hold afterwards: the loop must not be
// wedged (the pending timer comes due and a new dial happens), it must not
// busy-spin (having retried once, it goes back to waiting rather than
// hammering), and the jump must not produce a nonsensical wait.
func TestReconnect_MultiHourClockJumpMidBackoff(t *testing.T) {
	t.Parallel()

	hub := mem.NewHub()
	tr := &countingDeadTransport{inner: hub.Transport("jump-client:1")}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"dead-server": {Addr: "jump-nothing-here:1"},
	}

	clock := newJumpClock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return tr, nil },
		ceilingPolicy(),
		clock,
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// The first dial fails immediately (nothing is listening) and the loop
	// arms its first backoff timer. Nothing fires until the test says so.
	waitForDials(t, tr, 1, 5*time.Second)
	clock.waitForArms(t, 1, 5*time.Second)

	// Nothing should happen while the clock stands still. This is the
	// baseline the busy-spin check below is measured against: if the loop
	// retried without its timer, it would do so here too.
	time.Sleep(200 * time.Millisecond)
	if got := tr.dialCount(); got != 1 {
		t.Fatalf("with the clock stopped, dial count moved from 1 to %d — "+
			"the loop is retrying without waiting for its backoff timer", got)
	}

	// The suspend. Six hours at once, far beyond any interval the backoff
	// schedule can produce.
	for round := 1; round <= 3; round++ {
		before := tr.dialCount()
		armsBefore := clock.armCount()

		clock.Advance(6 * time.Hour)

		// No wedge, and a prompt re-dial: the timer the jump carried past
		// its deadline must actually deliver.
		waitForDials(t, tr, before+1, 5*time.Second)

		// No busy-spin: one jump releases one timer, so exactly one retry
		// should follow and the loop should then be waiting again. A loop
		// that mishandled the discontinuity (re-firing stale timers, or
		// computing a zero or negative wait from the huge elapsed time)
		// would keep dialing here without any further Advance.
		clock.waitForArms(t, armsBefore+1, 5*time.Second)
		time.Sleep(200 * time.Millisecond)
		if got := tr.dialCount(); got != before+1 {
			t.Fatalf("round %d: dial count went %d → %d after a single clock jump; "+
				"want exactly one retry, so the loop is spinning rather than waiting",
				round, before, got)
		}
	}
}

// TestReconnect_ClockJumpWhileConnectedThenDrop covers the other half: the
// elapsed-time reading rather than the timer. After a jump, the time since the
// last successful connection is measured in hours, which is far larger than
// anything an ordinary reconnect produces and larger than the stable-reset
// threshold. Dropping the session at that point must still recover cleanly.
func TestReconnect_ClockJumpWhileConnectedThenDrop(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hub := mem.NewHub()
	srvLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	srvT := hub.Transport("jump2-agent:1", mem.WithCert(srvLeaf))
	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, ln, rtr) }()

	cliT := hub.Transport("jump2-client:1", mem.WithCert(srvLeaf))

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"live-server": {Addr: "jump2-agent:1"},
	}

	clock := newJumpClock()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return cliT, nil },
		ceilingPolicy(),
		clock,
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	waitForPoolState(t, pool, "live-server", "connected", 10*time.Second)

	conn1, err := pool.Get(ctx, "live-server")
	if err != nil {
		t.Fatalf("Get (first): %v", err)
	}

	// Suspend while connected. The session's last-success timestamp is now
	// eight hours in the past as far as the daemon can tell.
	clock.Advance(8 * time.Hour)

	if got := clock.Since(clock.Now().Add(-8 * time.Hour)); got != 8*time.Hour {
		t.Fatalf("clock arithmetic: Since = %v, want 8h", got)
	}

	// Now the drop a resuming machine would find waiting for it.
	if err := conn1.CloseWithError(0, "test-forced drop after clock jump"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	// Recovery must still happen. A loop that mishandled the huge elapsed
	// reading would either wedge here or never return a fresh connection.
	conn2 := waitForDistinctConn(t, ctx, pool, "live-server", conn1, 10*time.Second)
	if conn2 == nil {
		t.Fatal("no replacement connection after a drop that followed a clock jump")
	}
}
