package daemon_test

// control_call_test.go tests SessionEntry.ControlCall and its pool-level
// accessor, SessionPool.ControlCall.
//
// The central property under test is the locking discipline: the entry
// mutex is held only long enough to copy the current control client, then
// released before fn ever runs. A naive implementation that holds the
// mutex for the call's own duration would stall State(), stall Get(), and
// can hang shutdown — see TestControlCall_DoesNotHoldTheEntryMutexAcrossTheCall
// and TestControlCall_RaceSafeUnderConcurrentClose, which is the most
// important test in this file.
//
// Every behavioural test runs against both a dial-mode entry and a
// listen-mode entry through the SessionPool/SessionEntry interfaces, so a
// divergence between the two implementations is a real test failure rather
// than something a reviewer has to notice by inspection.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- rig ---------------------------------------------------------------

// controlCallRig is the minimal shape a ControlCall test needs, regardless
// of which direction the underlying entry dials in. Building both a dial rig
// and a listen rig behind the same shape is what lets one test body run
// against both without a type switch anywhere in the test itself, mirroring
// the property ControlCall's own pool-level accessor has in production.
type controlCallRig struct {
	pool   daemon.SessionPool
	server string
	// connect brings a real agent online (if it is not already) and blocks
	// until the entry reports "connected". Only the subtests that need a
	// live control client call it.
	connect func(t *testing.T, ctx context.Context)

	closeOnce sync.Once
	closeFn   func()
}

// Close tears the rig down exactly once, however many times it is called —
// several tests in this file call pool.Close() explicitly mid-test to force
// a concurrent-shutdown interleaving, and t.Cleanup calls it again
// afterward.
func (r *controlCallRig) Close() {
	r.closeOnce.Do(func() {
		if r.closeFn != nil {
			r.closeFn()
		}
	})
}

// newForwardRig builds a single dial-mode ("fwd") server against an
// in-memory hub. If serveNow is true, a real agent is already listening at
// construction time, so the entry connects on its own with no further setup.
// If false, no listener exists yet and the entry sits in "connecting"
// forever until connect() is called.
func newForwardRig(t *testing.T, serveNow bool) *controlCallRig {
	t.Helper()

	hub := mem.NewHub()
	const agentAddr = "cc-fwd-agent:1"

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"fwd": {Addr: agentAddr}}

	ctx, cancel := context.WithCancel(context.Background())

	startAgent := func(t *testing.T) {
		t.Helper()
		leaf, _, err := mem.NewIdentity()
		if err != nil {
			t.Fatalf("NewIdentity: %v", err)
		}
		srvT := hub.Transport(agentAddr, mem.WithCert(leaf))
		ln, err := srvT.Listen()
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, nil)
		if err != nil {
			t.Fatalf("router.New: %v", err)
		}
		go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck
		t.Cleanup(func() { ln.Close() })
	}

	if serveNow {
		startAgent(t)
	}

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	cliT := hub.Transport("cc-fwd-client:1", mem.WithCert(clientLeaf))

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return cliT, nil },
		daemon.DefaultReconnectPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		cancel()
		t.Fatalf("NewRealPool: %v", err)
	}

	r := &controlCallRig{
		pool:   pool,
		server: "fwd",
		connect: func(t *testing.T, _ context.Context) {
			t.Helper()
			if !serveNow {
				startAgent(t)
			}
			waitForPoolState(t, pool, "fwd", "connected", 10*time.Second)
		},
	}
	r.closeFn = func() { pool.Close(); cancel() }
	t.Cleanup(r.Close)
	return r
}

// newListenRig builds a single listen-mode ("rev") server, reusing the
// existing reverseRig harness (listen_entry_test.go) so the two directions
// share exactly the same agent-side plumbing the rest of the package already
// trusts, rather than a second hand-rolled reverse-mode setup.
func newListenRig(t *testing.T) *controlCallRig {
	t.Helper()
	rr := newReverseRig(t)
	r := &controlCallRig{
		pool:   rr.pool,
		server: "rev",
		connect: func(t *testing.T, ctx context.Context) {
			t.Helper()
			rr.connectAgent(t, ctx)
			waitForPoolState(t, rr.pool, "rev", "connected", 10*time.Second)
		},
	}
	// reverseRig already registers its own t.Cleanup(pool.Close); this rig's
	// Close is a separate, independent no-op wrapper so both directions
	// expose the same Close() shape to a test that wants to force an early
	// shutdown without caring which kind of entry backs it.
	r.closeFn = func() { rr.pool.Close() }
	return r
}

// bothDirections is the shared rig table every behavioural test in this file
// runs against. Adding a third SessionEntry implementation in the future
// means adding one line here, not duplicating every test.
func bothDirections(serveNow bool) []struct {
	name string
	rig  func(t *testing.T) *controlCallRig
} {
	return []struct {
		name string
		rig  func(t *testing.T) *controlCallRig
	}{
		{"dial", func(t *testing.T) *controlCallRig { return newForwardRig(t, serveNow) }},
		{"listen", func(t *testing.T) *controlCallRig { return newListenRig(t) }},
	}
}

// ---- not yet connected: fn must never run -------------------------------

// TestControlCall_NotYetConnected_FnNeverCalled proves ControlCall refuses to
// call fn at all when the entry currently holds no control client — the nil
// check that makes the raw client's absence structurally safe to report
// rather than something a caller could accidentally dereference.
func TestControlCall_NotYetConnected_FnNeverCalled(t *testing.T) {
	t.Parallel()
	for _, tc := range bothDirections(false) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.rig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			fnCalled := make(chan struct{}, 1)
			err := r.pool.ControlCall(ctx, r.server, func(_ context.Context, _ *control.Client) error {
				select {
				case fnCalled <- struct{}{}:
				default:
				}
				return nil
			})
			if err == nil {
				t.Fatal("ControlCall succeeded against an entry with no control client yet")
			}
			select {
			case <-fnCalled:
				t.Fatal("ControlCall invoked fn even though no control client was available")
			default:
			}
		})
	}
}

// TestControlCall_DisabledServer_NotAvailable covers the third entry kind,
// disabledEntry, which is not part of the dial/listen shared table because a
// disabled server has no direction to speak of.
func TestControlCall_DisabledServer_NotAvailable(t *testing.T) {
	t.Parallel()

	disabled := false
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"off": {Addr: "127.0.0.1:1", Enabled: &disabled},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			t.Fatal("transport factory called for a disabled server")
			return nil, nil
		},
		daemon.DefaultReconnectPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	called := false
	callErr := pool.ControlCall(ctx, "off", func(context.Context, *control.Client) error {
		called = true
		return nil
	})
	if callErr == nil {
		t.Fatal("ControlCall succeeded against a disabled server")
	}
	if called {
		t.Fatal("ControlCall invoked fn for a disabled server")
	}
	if !strings.Contains(callErr.Error(), "disabled") {
		t.Errorf("ControlCall error = %q, want it to mention the server is disabled", callErr.Error())
	}
}

// ---- unknown server -------------------------------------------------------

// TestControlCall_UnknownServer_MatchesPoolsExistingNotFoundShape proves the
// pool-level accessor reuses the exact not-found error pool.Get already
// produces, rather than inventing a second error string for the same fact.
func TestControlCall_UnknownServer_MatchesPoolsExistingNotFoundShape(t *testing.T) {
	t.Parallel()
	r := newForwardRig(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, getErr := r.pool.Get(ctx, "does-not-exist")
	if getErr == nil || !strings.Contains(getErr.Error(), `unknown server "does-not-exist"`) {
		t.Fatalf("test precondition: pool.Get's own not-found error shape changed; got %v", getErr)
	}

	callErr := r.pool.ControlCall(ctx, "does-not-exist", func(context.Context, *control.Client) error {
		t.Error("fn invoked for an unknown server")
		return nil
	})
	if callErr == nil {
		t.Fatal("ControlCall succeeded for an unknown server name")
	}
	const want = `pool: unknown server "does-not-exist"`
	if callErr.Error() != want {
		t.Errorf("ControlCall error = %q, want exactly %q (mirroring pool.Get's own shape)", callErr.Error(), want)
	}
}

// ---- connected: fn actually runs against a working client ---------------

// TestControlCall_Connected_InvokesFnWithAWorkingClient proves the happy
// path end to end: once the entry is connected, ControlCall hands fn a
// client that can make a real RPC and get a real reply.
func TestControlCall_Connected_InvokesFnWithAWorkingClient(t *testing.T) {
	t.Parallel()
	for _, tc := range bothDirections(true) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.rig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r.connect(t, ctx)

			called := make(chan struct{}, 1)
			err := r.pool.ControlCall(ctx, r.server, func(cctx context.Context, c *control.Client) error {
				select {
				case called <- struct{}{}:
				default:
				}
				if c == nil {
					return errors.New("fn invoked with a nil client")
				}
				_, perr := c.PingRTT(cctx)
				return perr
			})
			if err != nil {
				t.Fatalf("ControlCall: %v", err)
			}
			select {
			case <-called:
			default:
				t.Fatal("ControlCall returned success without ever invoking fn")
			}
		})
	}
}

// ---- the lock must not be held across the call ----------------------------

// TestControlCall_DoesNotHoldTheEntryMutexAcrossTheCall is the test that
// proves the corrected design (copy-then-release-then-call), not merely the
// symptom (a race). fn is deliberately parked mid-call on a channel only the
// test controls; while it is parked, State() — which takes the same entry
// mutex for a plain field read — must return within a small, real bound, not
// "eventually". A naive accessor that held the mutex for fn's own duration
// would make State() block for as long as fn stays parked.
func TestControlCall_DoesNotHoldTheEntryMutexAcrossTheCall(t *testing.T) {
	for _, tc := range bothDirections(true) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.rig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r.connect(t, ctx)

			started := make(chan struct{})
			release := make(chan struct{})
			callErr := make(chan error, 1)
			go func() {
				callErr <- r.pool.ControlCall(ctx, r.server, func(context.Context, *control.Client) error {
					close(started)
					<-release
					return nil
				})
			}()

			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("ControlCall's fn never started")
			}

			const bound = 250 * time.Millisecond
			stateDone := make(chan struct{})
			go func() {
				_ = r.pool.State()
				close(stateDone)
			}()

			select {
			case <-stateDone:
			case <-time.After(bound):
				close(release)
				t.Fatalf("pool.State() did not return within %s while a ControlCall was parked mid-call; "+
					"the entry mutex appears to be held across the call", bound)
			}

			close(release)
			select {
			case err := <-callErr:
				if err != nil {
					t.Fatalf("ControlCall: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("ControlCall did not return after fn was released")
			}
		})
	}
}

// ---- race safety under a concurrent Close ----------------------------------

// TestControlCall_RaceSafeUnderConcurrentClose is the most important test in
// this file. It proves three things at once, under -race:
//
//  1. pool.Close() (which every entry's Close ultimately serves) returns
//     promptly even while a ControlCall is genuinely in flight against that
//     same entry — the SIGTERM-shutdown-hang shape this design exists to
//     avoid.
//  2. The parked call, once released, can safely use its copied client even
//     though Close has since nilled and torn down the entry's own field —
//     because ControlCall never handed the caller anything but a copy, there
//     is no reference left to race.
//  3. None of the above trips the race detector.
func TestControlCall_RaceSafeUnderConcurrentClose(t *testing.T) {
	for _, tc := range bothDirections(true) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.rig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r.connect(t, ctx)

			started := make(chan struct{})
			release := make(chan struct{})
			callDone := make(chan struct{})
			go func() {
				defer close(callDone)
				_ = r.pool.ControlCall(ctx, r.server, func(cctx context.Context, c *control.Client) error {
					close(started)
					<-release
					// Touch the (possibly already-torn-down) client after
					// release. This must fail cleanly if it fails at all —
					// never panic, never hang.
					_, perr := c.PingRTT(cctx)
					return perr
				})
			}()

			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("ControlCall's fn never started")
			}

			closeDone := make(chan struct{})
			go func() {
				r.Close()
				close(closeDone)
			}()

			select {
			case <-closeDone:
			case <-time.After(5 * time.Second):
				t.Fatal("Close() did not return while a ControlCall was in flight — " +
					"SIGTERM shutdown would hang on exactly this")
			}

			close(release)
			select {
			case <-callDone:
			case <-time.After(5 * time.Second):
				t.Fatal("ControlCall did not return after Close and release")
			}
		})
	}
}

// ---- bounded deadline -------------------------------------------------------

// TestControlCall_DeadlineIsBounded asserts the exact bound ControlCall
// enforces, not a range: a range assertion would still pass if the deadline
// were silently dropped and something else — the test's own outer context,
// in this harness — fired instead far later.
func TestControlCall_DeadlineIsBounded(t *testing.T) {
	for _, tc := range bothDirections(true) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.rig(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			r.connect(t, ctx)

			start := time.Now()
			err := r.pool.ControlCall(ctx, r.server, func(cctx context.Context, _ *control.Client) error {
				<-cctx.Done()
				return cctx.Err()
			})
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("ControlCall returned nil for a call whose fn waited on ctx expiry")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("ControlCall error = %v, want context.DeadlineExceeded", err)
			}

			const want = daemon.DefaultControlCallTimeout
			const tolerance = 750 * time.Millisecond
			if elapsed < want-tolerance || elapsed > want+tolerance {
				t.Fatalf("ControlCall's fn ran for %s; want %s ± %s "+
					"(if this is far larger, the deadline was not applied at all)",
					elapsed, want, tolerance)
			}
		})
	}
}

// ---- reverse-mode-only: displaced mid-call ---------------------------------

// TestControlCall_DisplacedMidCall_FailsCleanly exercises an interleaving
// only reverse mode can produce: a listenEntry's incumbent connection is
// mid-ControlCall when a newer authenticated peer displaces it. The
// displacer closes the incumbent's
// control client out from under the parked call. Because ControlCall already
// holds its own copy, the close does not race the pool's internal state —
// but the in-flight RPC against a now-closed client must still surface as an
// ordinary failure, not a panic or a hang.
func TestControlCall_DisplacedMidCall_FailsCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	r := newReverseRig(t)
	r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)

	started := make(chan struct{})
	release := make(chan struct{})
	callErr := make(chan error, 1)
	go func() {
		callErr <- r.pool.ControlCall(ctx, "rev", func(cctx context.Context, c *control.Client) error {
			close(started)
			<-release
			_, perr := c.PingRTT(cctx)
			return perr
		})
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("ControlCall's fn never started")
	}

	incumbent, err := r.pool.Get(ctx, "rev")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// A newer authenticated peer displaces the incumbent while the parked
	// call still holds a copy of the old (soon to be closed) client.
	r.connectAgent(t, ctx)
	if got := waitForDistinctConn(t, ctx, r.pool, "rev", incumbent, 15*time.Second); got == nil {
		t.Fatal("displacement never happened")
	}

	// Let the parked call proceed against the now-displaced client.
	close(release)

	select {
	case err := <-callErr:
		if err == nil {
			t.Fatal("ControlCall against a displaced session's client returned success; want a clean failure")
		}
		t.Logf("ControlCall against a displaced session failed as expected: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ControlCall against a displaced session's client hung instead of failing cleanly")
	}
}
