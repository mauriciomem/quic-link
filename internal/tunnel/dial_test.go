package tunnel_test

// @spec-handoff
// @interface DialAndServe(ctx context.Context, t transport.Transport, addr string, rtr *router.Router, policy backoff.Policy, clock Clock, opts ...ServeOpts) error
// @behavior
//   - After ServeConn returns from a connection that completed its handshake
//     and then dropped for an ordinary reason (not an auth failure, not a role
//     collision), the loop must consult policy.Backoff(attempt) and wait on the
//     channel returned by clock.After(d) before dialing again — the same
//     scheduling the dial-failure path already applies. Reaching ServeConn once
//     must not be treated as license to skip the wait on a later drop.
//   - When either t.Dial's error or the cause behind ServeConn returning
//     (context.Cause(conn.Context())) is a role collision recognised by
//     transport.IsRoleMismatch, DialAndServe returns that error immediately and
//     makes no further dial attempt, the same way it already stops for
//     transport.IsAuthFailed — a distinct and equally terminal condition.
// @edge-cases
//   - A role collision can surface at either check site depending on handshake
//     timing; both must be terminal on their own, independently.
//   - The attempt counter is reset to 0 by the connect that just succeeded, so
//     the first post-drop Backoff call under test is expected with n=0.
// @see ./dial.go

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/backoff"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// The agent connecting out instead of being connected to changes which end
// reopens a dropped link. It must change nothing about what the agent will
// serve: the route table is the only thing deciding what a peer may reach, and
// that has to hold whichever end opened the connection.

// zeroPolicy retries immediately, so a reconnect test is bounded by real work
// rather than by a schedule.
type zeroPolicy struct{}

func (zeroPolicy) Backoff(int) time.Duration  { return 0 }
func (zeroPolicy) StableAfter() time.Duration { return time.Second }

// recordingBackoffPolicy records every Backoff(n) call it receives, so a test
// can assert the reconnect loop actually consulted the schedule rather than
// merely observing that a reconnect eventually happened on its own. zeroPolicy
// cannot do this: it hands out zero regardless of whether anyone called it,
// which makes a test built on it structurally blind to whether the loop
// consulted the policy at all.
type recordingBackoffPolicy struct {
	mu   sync.Mutex
	seen []int
}

func (p *recordingBackoffPolicy) Backoff(n int) time.Duration {
	p.mu.Lock()
	p.seen = append(p.seen, n)
	p.mu.Unlock()
	return 10 * time.Millisecond
}

func (p *recordingBackoffPolicy) StableAfter() time.Duration { return time.Hour }

// calls returns a snapshot of every n passed to Backoff so far, in call order.
func (p *recordingBackoffPolicy) calls() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]int, len(p.seen))
	copy(out, p.seen)
	return out
}

// gatedClock is a Clock whose After never fires on its own: every channel it
// hands out stays open until the test calls release, at which point every
// pending (and every future) call resolves at once. This lets a test tell the
// difference between "the loop waited on the clock, and the wait just hasn't
// ended yet" and "the loop never waited on the clock in the first place" —
// the second is what a real elapsed-time measurement cannot distinguish from
// the first without flaking on timing.
type gatedClock struct {
	mu   sync.Mutex
	seen []time.Duration
	gate chan struct{}
	once sync.Once
}

func newGatedClock() *gatedClock {
	return &gatedClock{gate: make(chan struct{})}
}

func (c *gatedClock) Now() time.Time                  { return time.Now() }
func (c *gatedClock) Since(t time.Time) time.Duration { return time.Since(t) }

// After records the requested duration and returns a channel that only
// delivers once release has been called, regardless of d. The duration itself
// is not honoured — this clock's purpose is to prove the loop reached the
// wait point at all, not to reproduce real timing.
func (c *gatedClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.seen = append(c.seen, d)
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	go func() {
		<-c.gate
		ch <- time.Now()
	}()
	return ch
}

// release lets every pending and future After channel deliver. Safe to call
// more than once.
func (c *gatedClock) release() { c.once.Do(func() { close(c.gate) }) }

// afterCallCount reports how many times After has been called so far.
func (c *gatedClock) afterCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// countingDialer counts dials and can be told to fail.
type countingDialer struct {
	inner transport.Transport
	mu    sync.Mutex
	dials int
}

func (d *countingDialer) Dial(ctx context.Context, addr string) (transport.Conn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	return d.inner.Dial(ctx, addr)
}
func (d *countingDialer) Listen() (transport.Listener, error) { return d.inner.Listen() }
func (d *countingDialer) Close() error                        { return d.inner.Close() }
func (d *countingDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// waitingClient stands in for a daemon that waits: it accepts a connection and,
// like a real client, opens the control stream itself.
type waitingClient struct {
	ln transport.Listener
}

func newWaitingClient(t *testing.T, hub *mem.Hub, at string) *waitingClient {
	t.Helper()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	ln, err := hub.Transport(at, mem.WithCert(leaf)).Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return &waitingClient{ln: ln}
}

// accept takes one inbound connection and opens the control stream on it,
// which is what makes the session usable from the client's point of view.
func (w *waitingClient) accept(t *testing.T, ctx context.Context) transport.Conn {
	t.Helper()
	conn, err := w.ln.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	cc, err := tunnel.OpenControl(ctx, conn, "test client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("open control: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return conn
}

func agentDialRig(t *testing.T) (*mem.Hub, *countingDialer, string) {
	t.Helper()
	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	return hub, &countingDialer{inner: hub.Transport("dialing-agent:1", mem.WithCert(leaf))}, "waiting-client:1"
}

// TestDialAndServe_EnforcesTheRouteTable is the assertion that matters most.
// An agent that decided it was the client because it opened the connection
// would stop consulting the route table, and every target would silently
// become reachable. A deny policy is used rather than an unknown target
// because an unknown target is refused by lookup alone: only a target that
// exists and is refused proves the authorisation step actually ran.
func TestDialAndServe_EnforcesTheRouteTable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub, dialer, at := agentDialRig(t)
	client := newWaitingClient(t, hub, at)

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, denyEverything{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	go func() { _ = tunnel.DialAndServe(ctx, dialer, at, rtr, zeroPolicy{}, tunnel.WallClock{}) }()

	conn := client.accept(t, ctx)
	status := openAndRead(t, ctx, conn, "ssh")
	if status != proto.StatusUnauthorized {
		t.Fatalf("a known but forbidden target returned status %v, want unauthorized — "+
			"the agent is not consulting its route table when it opened the connection",
			status)
	}
}

// TestDialAndServe_UnknownTargetRefused covers the ordinary lookup failure.
func TestDialAndServe_UnknownTargetRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub, dialer, at := agentDialRig(t)
	client := newWaitingClient(t, hub, at)

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go func() { _ = tunnel.DialAndServe(ctx, dialer, at, rtr, zeroPolicy{}, tunnel.WallClock{}) }()

	conn := client.accept(t, ctx)
	if status := openAndRead(t, ctx, conn, "nope"); status != proto.StatusUnknownTarget {
		t.Errorf("unknown target returned status %v, want unknown_target", status)
	}
}

// TestDialAndServe_ReconnectsAfterDrop: the end that opened the connection is
// the end that must reopen it.
func TestDialAndServe_ReconnectsAfterDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hub, dialer, at := agentDialRig(t)
	client := newWaitingClient(t, hub, at)

	// A real listener behind the route, so "ok" means the stream was actually
	// carried rather than merely accepted.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, aerr := echo.Accept()
			if aerr != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echo.Addr().String()}, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go func() { _ = tunnel.DialAndServe(ctx, dialer, at, rtr, zeroPolicy{}, tunnel.WallClock{}) }()

	first := client.accept(t, ctx)
	if err := first.CloseWithError(0, "test-forced drop"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	// A second connection must arrive on its own, and must actually work
	// rather than merely having been dialed.
	second := client.accept(t, ctx)
	if status := openAndRead(t, ctx, second, "ssh"); status != proto.StatusOK {
		t.Errorf("after reconnect a known target returned status %v, want ok", status)
	}
	if dialer.count() < 2 {
		t.Errorf("dial count = %d, want at least 2", dialer.count())
	}
}

// pollUntilTrue polls cond every 5ms until it reports true or budget elapses.
// It returns whether cond became true within the budget, so a caller can
// t.Fatalf with a message that explains what the timeout means rather than a
// bare "timed out".
func pollUntilTrue(budget time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestDialAndServe_AppliesBackoffAfterPostHandshakeDrop is the regression test
// for the defect where a connection that completes its handshake and later
// drops skips the reconnect schedule entirely, even though a connection that
// never completed its handshake (an ordinary dial failure) correctly waits on
// it. Both paths return to the same t.Dial call at the top of the loop, so
// nothing about the retry should depend on how far the previous attempt got —
// but today it does.
//
// A fake clock whose After blocks until the test releases it is used
// deliberately instead of measuring elapsed wall time: this loop already
// resets its own attempt counter to zero on every successful connect, so an
// implementation that skips the wait still eventually reconnects — the defect
// is invisible to any test that only checks "did it reconnect", it is visible
// only in whether the schedule was ever consulted and whether the loop
// actually blocked on it before trying again.
func TestDialAndServe_AppliesBackoffAfterPostHandshakeDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hub, dialer, at := agentDialRig(t)
	client := newWaitingClient(t, hub, at)

	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	policy := &recordingBackoffPolicy{}
	clock := newGatedClock()
	t.Cleanup(clock.release)

	go func() { _ = tunnel.DialAndServe(ctx, dialer, at, rtr, policy, clock) }()

	first := client.accept(t, ctx)
	if dialer.count() != 1 {
		t.Fatalf("dial count = %d before any drop, want exactly 1", dialer.count())
	}

	// An ordinary drop: neither an auth failure nor a role collision, the
	// same close code the existing TestDialAndServe_ReconnectsAfterDrop uses.
	if err := first.CloseWithError(0, "test-forced drop"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	if !pollUntilTrue(3*time.Second, func() bool { return clock.afterCallCount() >= 1 }) {
		t.Fatalf("clock.After was never called within the budget after a post-handshake drop; "+
			"the loop redialed (dial count = %d) without consulting the backoff schedule at all — "+
			"a connection that completed its handshake and then dropped is skipping the wait that "+
			"an ordinary dial failure correctly takes", dialer.count())
	}

	if calls := policy.calls(); len(calls) == 0 {
		t.Fatal("policy.Backoff was never called after a post-handshake drop; " +
			"the loop is reconnecting without consulting the schedule")
	} else if calls[0] != 0 {
		t.Errorf("first post-drop Backoff call used attempt=%d, want 0 — "+
			"attempt was reset to 0 by the connect that just succeeded", calls[0])
	}

	// The wait must actually gate the next dial, not merely have been asked
	// for and then ignored: while the gate stays closed, no second dial may
	// happen.
	time.Sleep(50 * time.Millisecond)
	if got := dialer.count(); got != 1 {
		t.Fatalf("dial count = %d while the backoff wait was still pending, want exactly 1 — "+
			"the loop redialed before its own clock.After channel delivered", got)
	}

	// Releasing the gate must let the loop resume and reconnect, so this is
	// not merely detecting a permanent wedge either.
	clock.release()
	if !pollUntilTrue(5*time.Second, func() bool { return dialer.count() >= 2 }) {
		t.Fatalf("dial count = %d after releasing the backoff wait, want at least 2 — "+
			"the loop did not resume after the clock delivered", dialer.count())
	}
}

// TestDialAndServe_GivesUpOnRoleMismatch_FromDialError covers the first of the
// two sites in the loop that must treat a role collision as terminal: the
// error returned directly by t.Dial. Today only transport.IsAuthFailed is
// checked there, so a role-mismatch-shaped error falls through to the
// ordinary "unreachable; retrying" backoff path and is retried forever —
// exactly the one misconfiguration (both ends holding one key) that cannot
// self-heal by retrying.
func TestDialAndServe_GivesUpOnRoleMismatch_FromDialError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	// mem.FailDial makes every Dial return this error regardless of whether a
	// listener exists, mirroring TestDialAndServe_GivesUpWhenIdentityRejected's
	// use of the same seam for the auth-failure terminal path. Wrapping
	// transport.ErrRoleMismatch is what transport.IsRoleMismatch checks first.
	roleMismatchErr := fmt.Errorf("dial: %w", transport.ErrRoleMismatch)
	colliding := &countingDialer{
		inner: hub.Transport("colliding-agent:1", mem.WithCert(leaf), mem.FailDial(roleMismatchErr)),
	}
	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- tunnel.DialAndServe(ctx, colliding, "anywhere:1", rtr, zeroPolicy{}, tunnel.WallClock{})
	}()

	select {
	case err := <-done:
		if !transport.IsRoleMismatch(err) {
			t.Errorf("returned %v, want a role mismatch", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("kept retrying a role collision the peer will never resolve by itself")
	}
	if got := colliding.count(); got != 1 {
		t.Errorf("dial count = %d, want exactly 1: a role collision at Dial must not be retried", got)
	}
}

// TestDialAndServe_GivesUpOnRoleMismatch_FromConnCloseCause covers the second
// site: the cause behind ServeConn returning, read via
// context.Cause(conn.Context()). This is where a role collision actually
// surfaces in practice, because the collision is only detected after both
// ends' handshakes have already completed — the dialing side's own Dial call
// succeeds, and the rejection arrives as the reason its connection closed. The
// waiting listener here is deliberately given the SAME certificate as the
// dialing agent's own transport, which is the misconfiguration itself (one
// keypair copied to both ends): ServeConn's own role check (shared with the
// accepting path, see role_mismatch_test.go) sees the peer presenting our own
// identity and closes with the role-mismatch code before ever accepting a
// stream, which cancels the dialing side's connection context with the
// collision as its cause. newWaitingClient is not reused here because it
// mints its own fresh, distinct identity internally — using it would dial a
// peer with a different key, which is not what this test needs to reproduce.
func TestDialAndServe_GivesUpOnRoleMismatch_FromConnCloseCause(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub := mem.NewHub()
	shared, sharedPin, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	dialer := &countingDialer{inner: hub.Transport("colliding-dialer:1", mem.WithCert(shared))}

	// The waiting side presents the identical certificate — the collision.
	waiterLn, err := hub.Transport("colliding-waiter:1", mem.WithCert(shared)).Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { waiterLn.Close() })

	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- tunnel.DialAndServe(ctx, dialer, "colliding-waiter:1", rtr, zeroPolicy{}, tunnel.WallClock{},
			tunnel.ServeOpts{OwnPin: sharedPin})
	}()

	// Accept the raw connection only — do not open a control stream on it.
	// ServeConn refuses the role collision before it ever accepts a stream, so
	// there is nothing here for a control open to succeed against.
	if _, err := waiterLn.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	select {
	case err := <-done:
		if !transport.IsRoleMismatch(err) {
			t.Errorf("returned %v, want a role mismatch", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("kept retrying a role collision surfaced as a connection-close cause")
	}
	if got := dialer.count(); got != 1 {
		t.Errorf("dial count = %d, want exactly 1: a role collision surfaced after ServeConn "+
			"returns must not be retried", got)
	}
}

// TestDialAndServe_RetriesAfterNoPeerIdentityClose is the regression test for
// the close-code overload at the DialAndServe level: a connection-close cause
// carrying tunnel.NoPeerIdentityCode must NOT be classified as a role
// mismatch by transport.IsRoleMismatch, so the loop keeps retrying rather
// than giving up permanently after one dial. Before this fix, serve.go sent
// the same numeric code for "no peer identity" as for a genuine role
// collision, so this connection-close cause was indistinguishable from one
// and DialAndServe returned immediately instead of reconnecting.
func TestDialAndServe_RetriesAfterNoPeerIdentityClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	dialer := &countingDialer{inner: hub.Transport("noident-dialer:1", mem.WithCert(leaf))}

	// The waiting side closes every accepted connection with
	// tunnel.NoPeerIdentityCode, standing in for serveConn's defense-in-depth
	// branch without needing an unreachable real handshake state.
	waiterLn, err := hub.Transport("noident-waiter:1").Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { waiterLn.Close() })
	go func() {
		for {
			conn, err := waiterLn.Accept(ctx)
			if err != nil {
				return
			}
			_ = conn.CloseWithError(uint64(tunnel.NoPeerIdentityCode), "no peer identity")
		}
	}()

	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- tunnel.DialAndServe(ctx, dialer, "noident-waiter:1", rtr, zeroPolicy{}, tunnel.WallClock{})
	}()

	if !pollUntilTrue(10*time.Second, func() bool { return dialer.count() >= 2 }) {
		t.Fatalf("dial count = %d, want at least 2 — a no-peer-identity close "+
			"must not be classified as a role mismatch and must not stop the retry loop",
			dialer.count())
	}
	cancel()
	<-done
}

// TestDialAndServe_GivesUpWhenIdentityRejected: retrying a rejected identity
// forever would bury the one message that explains the problem.
func TestDialAndServe_GivesUpWhenIdentityRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	rejecting := &countingDialer{
		inner: hub.Transport("rejected-agent:1", mem.WithCert(leaf), mem.FailDial(transport.ErrAuthFailed)),
	}
	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- tunnel.DialAndServe(ctx, rejecting, "anywhere:1", rtr, zeroPolicy{}, tunnel.WallClock{})
	}()

	select {
	case err := <-done:
		if !transport.IsAuthFailed(err) {
			t.Errorf("returned %v, want an authentication failure", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("kept retrying an identity the peer will never accept")
	}
	if got := rejecting.count(); got != 1 {
		t.Errorf("dial count = %d, want exactly 1: a rejected identity must not be retried", got)
	}
}

// TestDialAndServe_StopsOnContextCancel keeps shutdown prompt and leak-free.
func TestDialAndServe_StopsOnContextCancel(t *testing.T) {
	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	dialer := &countingDialer{inner: hub.Transport("lonely-agent:1", mem.WithCert(leaf))}
	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- tunnel.DialAndServe(ctx, dialer, "nothing-here:1", rtr, zeroPolicy{}, tunnel.WallClock{})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop when its context was cancelled")
	}
}

// TestDialAndServe_UsesSharedBackoff proves the loop takes the shared schedule
// rather than a second copy that could drift from it.
func TestDialAndServe_UsesSharedBackoff(t *testing.T) {
	var _ backoff.Policy = zeroPolicy{}
	p := backoff.Default()
	seen := map[time.Duration]struct{}{}
	for i := 0; i < 50; i++ {
		seen[p.Backoff(5)] = struct{}{}
	}
	if len(seen) < 2 {
		t.Error("the schedule handed to the agent's loop is not jittered")
	}
}

// TestBothDialHint_MentionsTheOtherPossibility: two ends both configured to
// connect out look exactly like an unreachable peer, so the retry log has to
// raise the possibility itself once "not started yet" stops being likely.
func TestBothDialHint_MentionsTheOtherPossibility(t *testing.T) {
	buf := captureTunnelLogs(t)

	hub := mem.NewHub()
	leaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	dialer := &countingDialer{inner: hub.Transport("hint-agent:1", mem.WithCert(leaf))}
	rtr, err := router.New(nil, router.AllowAll{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tunnel.DialAndServe(ctx, dialer, "nothing-here:1", rtr, zeroPolicy{}, tunnel.WallClock{})
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "neither end is waiting") {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Errorf("no hint about both ends connecting out after repeated failures; log was:\n%s", buf.String())
}

// denyEverything refuses every target while leaving the route table populated,
// so the authorisation step is the only thing that can produce the refusal.
type denyEverything struct{}

func (denyEverything) Authorize(router.Identity, proto.Header) error {
	return errors.New("denied by test policy")
}

// openAndRead opens one stream naming target and returns the status the agent
// replied with.
func openAndRead(t *testing.T, ctx context.Context, conn transport.Conn, target string) proto.Status {
	t.Helper()
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := proto.WriteHeader(stream, proto.Header{Kind: proto.KindTCP, Target: target}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	resp, err := proto.ReadResponse(stream)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// Only the verdict is under test here. Tear the stream down so an accepted
	// one does not leave a splice running past the end of the test.
	stream.Reset(proto.StreamResetCode)
	return resp.Status
}

// captureTunnelLogs redirects the default logger into a race-safe buffer.
func captureTunnelLogs(t *testing.T) *logBuffer {
	t.Helper()
	var buf logBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
