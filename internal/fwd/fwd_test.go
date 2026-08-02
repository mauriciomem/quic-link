package fwd_test

// fwd_test.go covers the accept loop's shutdown-registry behavior — the
// highest-risk piece of this package (F10) — using the Attacher injection
// seam and real data flow for synchronization rather than tuned sleeps
// (F17). TestMain runs under a goleak guard from the package's first commit,
// since cmd/quic-link has none and this is the most goroutine-lifecycle-
// sensitive code in the tree.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/fwd"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---- test doubles ------------------------------------------------------------

// scriptedAttacher implements fwd.Attacher for tests. Configure dialAddr for
// the common case (dial a real TCP address and hand back the resulting real
// connection — this is what gives half-close/CloseWrite semantics that a
// net.Pipe() conn does not have), or onCall for full control over each
// individual call, including blocking a call on a channel for deterministic
// interleaving with a shutdown.
type scriptedAttacher struct {
	dialAddr string
	onCall   func(n int) (net.Conn, error)

	mu    sync.Mutex
	calls int
}

func (a *scriptedAttacher) Attach(_, _ string, _ map[string]string) (net.Conn, error) {
	a.mu.Lock()
	a.calls++
	n := a.calls
	a.mu.Unlock()

	if a.onCall != nil {
		return a.onCall(n)
	}
	return net.Dial("tcp4", a.dialAddr)
}

// startEchoServer starts a TCP echo server standing in for "the far side
// reached through the daemon." Returns the listener so a test can dial it
// (for the Attacher to point at) or close it directly to simulate the daemon
// disappearing out from under an active forward.
func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startEchoServer: listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c) //nolint:errcheck
				c.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mustListen: %v", err)
	}
	return ln
}

// runForwarder starts f.Run(ctx) in its own goroutine and returns a channel
// that closes when Run returns, so tests can synchronize on real completion
// (Run's own documented guarantee: closed listener, no more accepts,
// RegistrySize zero) rather than a sleep.
func runForwarder(f *fwd.Forwarder, ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()
	return done
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: did not complete within 5s", what)
	}
}

// ---- 1. happy path: byte-exact round trip ------------------------------------

func TestForwarder_HappyPath_ByteExact(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)
	att := &scriptedAttacher{dialAddr: echoLn.Addr().String()}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)

	c, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	payload := []byte("hello-fwd-world")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}
	c.Close()

	cancel()
	waitDone(t, done, "Run")
	if n := f.RegistrySize(); n != 0 {
		t.Errorf("registry not drained: %d entries remain", n)
	}
}

// ---- 2. half-close from the local side propagates ----------------------------

func TestForwarder_HalfClose_ResponseStillDrains(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)
	att := &scriptedAttacher{dialAddr: echoLn.Addr().String()}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)
	defer func() { cancel(); waitDone(t, done, "Run") }()

	c, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	tc := c.(*net.TCPConn)

	payload := []byte("half-close-payload")
	if _, err := tc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The read direction must still work after the local write-half-close —
	// this is the scp-style half-close property (FIN, not a reset).
	got, err := io.ReadAll(tc)
	if err != nil {
		t.Fatalf("ReadAll after CloseWrite: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("half-close echo mismatch: got %q want %q", got, payload)
	}
}

// ---- 3. unknown target: preflight and startup are covered by cmd-level and
// preflight_test.go tests; this package additionally covers "many concurrent
// connections" and the shutdown-registry scenarios below.

// ---- many concurrent connections; registry ends at zero ----------------------

func TestForwarder_ManyConcurrent_ByteExact_RegistryDrains(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)
	att := &scriptedAttacher{dialAddr: echoLn.Addr().String()}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			c, err := net.Dial("tcp4", localLn.Addr().String())
			if err != nil {
				t.Errorf("conn %d: dial: %v", i, err)
				return
			}
			defer c.Close()
			payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
			if _, err := c.Write(payload); err != nil {
				t.Errorf("conn %d: write: %v", i, err)
				return
			}
			got := make([]byte, len(payload))
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Errorf("conn %d: read: %v", i, err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("conn %d: mismatch: got %v want %v", i, got, payload)
			}
		}(i)
	}
	wg.Wait()

	cancel()
	waitDone(t, done, "Run")
	if got := f.RegistrySize(); got != 0 {
		t.Errorf("registry not drained after %d concurrent forwards: %d remain", n, got)
	}
}

// ---- connect-then-immediately-disconnect with zero bytes ---------------------

// TestForwarder_ZeroByteDisconnect_DeregistersCleanly is the one test in this
// package that polls RegistrySize instead of synchronizing on an event: a
// connection that sends no bytes at all produces no data-flow event to wait
// on, so a short, bounded, converging poll is the correct tool — it can never
// report success before the real state matches, unlike a single fixed sleep
// followed by one check.
func TestForwarder_ZeroByteDisconnect_DeregistersCleanly(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)
	att := &scriptedAttacher{dialAddr: echoLn.Addr().String()}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)
	defer func() { cancel(); waitDone(t, done, "Run") }()

	c, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	c.Close() // zero bytes exchanged

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f.RegistrySize() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("registry did not drain to zero: %d entries remain", f.RegistrySize())
}

// ---- 8. shutdown-mid-active-forward -------------------------------------------

// TestForwarder_ShutdownMidActiveForward is the test most at risk of becoming
// a "green test over a dead path": it synchronizes on real bytes actually
// arriving back from the echo target (proving the splice is genuinely
// active) before cancelling, then asserts via a real blocking Read (bounded
// by a deadline, not inferred from timing) that the local leg is reset
// promptly, and via RegistrySize that the shutdown sweep fully drained.
func TestForwarder_ShutdownMidActiveForward(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)
	att := &scriptedAttacher{dialAddr: echoLn.Addr().String()}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)

	c, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer c.Close()

	payload := []byte("active-forward")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read (proving the splice is active): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch before shutdown: got %q want %q", got, payload)
	}

	// The splice is now genuinely active (real bytes flowed both ways).
	// Cancel and require the local leg to be reset promptly rather than hang.
	cancel()

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, rerr := c.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("expected the local leg to be reset after shutdown, got a clean read")
	}

	waitDone(t, done, "Run")
	if got := f.RegistrySize(); got != 0 {
		t.Errorf("registry not drained after shutdown-mid-forward: %d remain", got)
	}
}

// ---- 9. connection accepted at the exact moment shutdown begins --------------

// TestForwarder_AcceptVsShutdownRace is the direct test of F10's race fix. It
// uses the Attacher seam to block a call to Attach until the test has
// deterministically observed (via a real connection reset, not a sleep) that
// the shutdown sweep has already run — proving the registration-before-Attach
// ordering closes the race rather than merely appearing to in a lucky timing
// window.
func TestForwarder_AcceptVsShutdownRace(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)

	started := make(chan struct{})
	proceed := make(chan struct{})
	att := &scriptedAttacher{onCall: func(n int) (net.Conn, error) {
		close(started)
		<-proceed
		return net.Dial("tcp4", echoLn.Addr().String())
	}}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)

	c, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer c.Close()

	// Wait for handleConn to have registered (register happens before Attach
	// is called) and to now be blocked inside Attach.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Attach was never called")
	}

	// Begin shutdown while the connection is registered but has no remote
	// leg yet. The sweep must reset the local leg right now.
	cancel()

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, rerr := c.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("expected the shutdown sweep to reset the local leg before Attach returned")
	}

	// Only now unblock the still-in-flight Attach call, proving the exact
	// race: a connection accepted right at the shutdown boundary must not
	// slip past the sweep even though its Attach call resolves afterward.
	close(proceed)

	waitDone(t, done, "Run")
	if got := f.RegistrySize(); got != 0 {
		t.Errorf("registry not drained after the race scenario: %d remain", got)
	}
}

// ---- 10. daemon-dies-mid-forward ----------------------------------------------

// TestForwarder_DaemonDiesMidForward mirrors the project's own "green test
// over a dead path" lesson directly: it proves the local leg tears down
// within a bounded time when the remote leg vanishes out from under an
// active splice, that a subsequent Attach failure is handled cleanly, and
// that fwd keeps listening and accepting new connections afterward.
func TestForwarder_DaemonDiesMidForward(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)

	var mu sync.Mutex
	var remotes []net.Conn
	att := &scriptedAttacher{onCall: func(n int) (net.Conn, error) {
		if n == 2 {
			return nil, errors.New("simulated: daemon unreachable")
		}
		c, err := net.Dial("tcp4", echoLn.Addr().String())
		if err == nil {
			mu.Lock()
			remotes = append(remotes, c)
			mu.Unlock()
		}
		return c, err
	}}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)
	defer func() { cancel(); waitDone(t, done, "Run") }()

	// Connection 1: establish, confirm real byte flow (proves the splice is
	// genuinely active before we kill it).
	c1, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.Close()
	if _, err := c1.Write([]byte("x")); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	buf1 := make([]byte, 1)
	c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c1, buf1); err != nil {
		t.Fatalf("c1 read (proving active): %v", err)
	}

	// Simulate the daemon dying: sever the remote leg directly.
	mu.Lock()
	remotes[0].Close()
	mu.Unlock()

	c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, rerr := c1.Read(buf1); rerr == nil {
		t.Fatal("expected c1's local leg to tear down when the remote leg vanished")
	}

	// Connection 2: the Attacher's second call fails (simulated daemon-down
	// window). fwd must handle this cleanly — no crash, no hang — and keep
	// listening.
	c2, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, rerr := c2.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("expected c2 to be reset after an Attach failure")
	}

	// Connection 3: the Attacher succeeds again — fwd is still listening and
	// functional after both the mid-forward death and the attach failure.
	c3, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial c3: %v", err)
	}
	defer c3.Close()
	if _, err := c3.Write([]byte("y")); err != nil {
		t.Fatalf("c3 write: %v", err)
	}
	buf3 := make([]byte, 1)
	c3.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c3, buf3); err != nil {
		t.Fatalf("c3 read: %v", err)
	}
	if buf3[0] != 'y' {
		t.Errorf("c3 echo mismatch: got %q want %q", buf3, "y")
	}
}

// ---- local concurrency bound (F16) --------------------------------------------

func TestForwarder_LocalConcurrencyCap_RefusesCleanly(t *testing.T) {
	t.Parallel()
	echoLn := startEchoServer(t)
	localLn := mustListen(t)

	// The Attacher blocks forever so the one permitted forward never
	// completes, letting the test deterministically observe the cap being
	// full rather than racing against a fast attach.
	release := make(chan struct{})
	att := &scriptedAttacher{onCall: func(n int) (net.Conn, error) {
		<-release
		return net.Dial("tcp4", echoLn.Addr().String())
	}}
	f := fwd.New("server1", "pg", localLn, att, fwd.Options{MaxConcurrent: 1})

	ctx, cancel := context.WithCancel(context.Background())
	done := runForwarder(f, ctx)
	defer func() { close(release); cancel(); waitDone(t, done, "Run") }()

	c1, err := net.Dial("tcp4", localLn.Addr().String())
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.Close()

	// Wait for c1 to occupy the single slot (it registers before Attach is
	// called, so RegistrySize reaching 1 proves the slot is held).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && f.RegistrySize() != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if f.RegistrySize() != 1 {
		t.Fatalf("c1 never occupied the concurrency slot")
	}

	// c2 must be refused (reset) immediately, since the cap is exhausted. The
	// reset can land during the dial handshake itself (net.Dial returns an
	// error directly, e.g. "connection reset by peer") or just after it
	// completes (the subsequent Read fails) — fwd resets fast enough that
	// either is a valid, non-flaky observation of the same refusal, so both
	// are accepted as proof rather than only the second.
	c2, dialErr := net.Dial("tcp4", localLn.Addr().String())
	if dialErr != nil {
		return // refused during the dial handshake itself — acceptable.
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, rerr := c2.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("expected c2 to be refused (reset) while the concurrency cap is full")
	}
}
