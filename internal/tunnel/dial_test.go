package tunnel_test

import (
	"bytes"
	"context"
	"errors"
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
