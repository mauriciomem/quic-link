/**
 * @spec-handoff
 * @interface OpenWindow(pin string, ttl time.Duration) (*Window, error); (*Window) IsOpen/Blob/Deadline/Attempt(src netip.Addr, proof, ekm []byte) Status/WaitResult(ctx) (Result, bool)/Close/Status() WindowStatus; sourceKey(netip.Addr) (netip.Prefix, bool); seam openWindowWith(pin, ttl, windowOpts{now, afterFunc, rand, verify, budget, bound})
 * @behavior
 *   - ttl 0 -> DefaultWindowTTL (2m); ttl < 0 -> ErrWindowTTL; pin via NewBlob (ParsePinStrict, error wraps); deadline = now().Add(ttl) (monotonic kept); timer armed with afterFunc(ttl, expire)
 *   - IsOpen = !closed && now().Before(deadline), never takes the lock; Blob() = Encode() only while open
 *   - Attempt, one critical section per window: open check (lazy expiry) -> verify runs exactly once on EVERY path (real secret if open, else the stand-in) -> closed: window_closed -> new key at bound: rate_limited, nothing evicted -> key with failures >= 5: rate_limited (the 6th attempt of a source is rate_limited even with a VALID proof) -> valid: close as ReasonPaired before returning, ok -> else failures++, bad_proof
 *   - Every close (paired, expired by timer or lazily, Close) happens exactly once under the lock: zero the held secret array, stand-in = 16 bytes from opts.rand, stop the timer, set Result, release WaitResult, drop the table
 *   - Source key: Unmap() first, then IPv4 /32 or IPv6 /64 (zone dropped); table holds at most 1024 keys
 *   - WindowStatus: window-wide numbers only (Open, Deadline, PerSourceBudget=5, SourcesTracked, SourcesExhausted, SourceSlotsFree); closed -> Open false, zero counts
 * @edge-cases
 *   - nil *Window: closed; IsOpen false, Blob "", zero Deadline/Status counts, Attempt window_closed
 *   - invalid source address -> rate_limited, no table entry, no verify call (unreachable from Serve)
 *   - opts.rand all-zero or failing -> fixed non-zero stand-in (bounded, no unbounded retry); window still closes
 *   - WaitResult returns false only when ctx ends first; Close idempotent; a later Close/timer never changes Result
 * @see ./proof.go (VerifyProof refuses a zero key early) ./blob.go (secret behind a closure) ./export_test.go
 */

package pairing_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/pairing"
)

// Budget values: 5 failed proofs per source key, 1024 source keys.
const (
	wantBudget = 5
	wantBound  = 1024
)

var (
	windowPin = func() string {
		p := sha256.Sum256([]byte("window listener spki"))
		return base64.StdEncoding.EncodeToString(p[:])
	}()
	testEKM  = bytes.Repeat([]byte{0x22}, pairing.EKMLength)
	badProof = bytes.Repeat([]byte{0x01}, pairing.ProofLength)
	zeroKey  [pairing.SecretLen]byte
)

// fakeClock is an injectable clock. It starts at time.Now(), so its readings
// carry a monotonic component like the real clock's.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeTimer counts Stop calls.
type fakeTimer struct{ stops atomic.Int32 }

func (f *fakeTimer) Stop() bool { return f.stops.Add(1) == 1 }

// fakeTimers records the window's afterFunc call so a test can fire it.
type fakeTimers struct {
	mu    sync.Mutex
	armed int
	d     time.Duration
	f     func()
	timer *fakeTimer
}

func (ft *fakeTimers) afterFunc(d time.Duration, f func()) pairing.Stopper {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.armed++
	ft.d, ft.f, ft.timer = d, f, &fakeTimer{}
	return ft.timer
}

func (ft *fakeTimers) state() (armed int, d time.Duration, stops int32) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if ft.timer != nil {
		stops = ft.timer.stops.Load()
	}
	return ft.armed, ft.d, stops
}

// fire runs the armed callback on the calling goroutine.
func (ft *fakeTimers) fire(t *testing.T) {
	t.Helper()
	ft.mu.Lock()
	f := ft.f
	ft.mu.Unlock()
	if f == nil {
		t.Fatal("OpenWindow armed no timer through afterFunc")
	}
	f()
}

// verifyLog wraps pairing.VerifyProof and records every call. With gate set,
// the first call signals entered and blocks until gate is closed.
type verifyLog struct {
	mu      sync.Mutex
	keys    [][pairing.SecretLen]byte
	lens    []int
	ekms    [][]byte
	gots    [][]byte
	gate    chan struct{}
	entered chan struct{}
}

func (v *verifyLog) verify(secret, ekm, got []byte) bool {
	v.mu.Lock()
	var k [pairing.SecretLen]byte
	copy(k[:], secret)
	v.keys = append(v.keys, k)
	v.lens = append(v.lens, len(secret))
	v.ekms = append(v.ekms, bytes.Clone(ekm))
	v.gots = append(v.gots, bytes.Clone(got))
	first := len(v.keys) == 1
	v.mu.Unlock()
	if first && v.gate != nil {
		close(v.entered)
		<-v.gate
	}
	return pairing.VerifyProof(secret, ekm, got)
}

func (v *verifyLog) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.keys)
}

// last returns the key, key length, ekm and proof of the most recent call.
func (v *verifyLog) last(t *testing.T) (key [pairing.SecretLen]byte, n int, ekm, got []byte) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) == 0 {
		t.Fatal("verify was never called")
	}
	i := len(v.keys) - 1
	return v.keys[i], v.lens[i], v.ekms[i], v.gots[i]
}

// patternReader yields b, b+1, b+2, ... It stands in for crypto/rand so the
// stand-in key is predictable and distinct from any real secret.
type patternReader struct {
	mu sync.Mutex
	b  byte
}

func (r *patternReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

// patternKey is the first SecretLen bytes a fresh patternReader{b} yields.
func patternKey(b byte) (k [pairing.SecretLen]byte) {
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

const standInSeed = 0x5A

// winHarness is a window opened with a fake clock, fake timer, recording
// verify and a pattern rand.
type winHarness struct {
	w      *pairing.Window
	clock  *fakeClock
	timers *fakeTimers
	vlog   *verifyLog
}

func openTest(t *testing.T, ttl time.Duration, mods ...func(*pairing.WindowOpts)) *winHarness {
	t.Helper()
	h := &winHarness{clock: newFakeClock(), timers: &fakeTimers{}, vlog: &verifyLog{}}
	o := pairing.WindowOpts{
		Now:       h.clock.Now,
		AfterFunc: h.timers.afterFunc,
		Rand:      &patternReader{b: standInSeed},
		Verify:    h.vlog.verify,
	}
	for _, m := range mods {
		m(&o)
	}
	w, err := pairing.OpenWindowWith(windowPin, ttl, o)
	if err != nil {
		t.Fatalf("OpenWindowWith: %v", err)
	}
	if w == nil {
		t.Fatal("OpenWindowWith returned a nil window and no error")
	}
	t.Cleanup(w.Close)
	h.w = w
	return h
}

// gated makes the harness's first verify call block until released.
func (h *winHarness) gated(t *testing.T) (release func()) {
	t.Helper()
	h.vlog.gate = make(chan struct{})
	h.vlog.entered = make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(h.vlog.gate) }) }
	t.Cleanup(release)
	return release
}

// waitEntered waits until the gated verify call is running.
func (h *winHarness) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-h.vlog.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Attempt never called verify")
	}
}

// secretOf returns the window's join secret, read back from its blob.
func secretOf(t *testing.T, w *pairing.Window) [pairing.SecretLen]byte {
	t.Helper()
	b, err := pairing.ParseBlob(w.Blob())
	if err != nil {
		t.Fatalf("ParseBlob(w.Blob()) while open: %v", err)
	}
	return b.Secret()
}

func validProof(t *testing.T, w *pairing.Window) []byte {
	t.Helper()
	s := secretOf(t, w)
	return pairing.Proof(s[:], testEKM)
}

// waitResult calls WaitResult with a 5 s safety deadline.
func waitResult(t *testing.T, w *pairing.Window) (pairing.Result, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.WaitResult(ctx)
}

// v4 returns the i-th address of 10.0.0.0/8 (i < 2^24).
func v4(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

// leakCheck registers a goleak check that runs after every other cleanup.
// goleak.VerifyTestMain skips its check once any test failed, so tests that
// start goroutines check for themselves.
func leakCheck(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
}

// nonCanonicalPin flips unused low bits of the character before "=".
func nonCanonicalPin(t *testing.T, canon string) string {
	t.Helper()
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := len(canon) - 2
	nc := canon[:i] + string(alpha[strings.IndexByte(alpha, canon[i])|1]) + canon[i+1:]
	if nc == canon {
		t.Fatal("test bug: non-canonical pin equals the canonical one")
	}
	return nc
}

func TestOpenWindow_DefaultsAndValidation(t *testing.T) {
	if pairing.DefaultWindowTTL != 2*time.Minute {
		t.Fatalf("DefaultWindowTTL = %v, want 2m", pairing.DefaultWindowTTL)
	}

	for _, tc := range []struct {
		ttl, want time.Duration
	}{{0, 2 * time.Minute}, {30 * time.Second, 30 * time.Second}} {
		h := openTest(t, tc.ttl)
		if got, want := h.w.Deadline(), h.clock.Now().Add(tc.want); !got.Equal(want) {
			t.Fatalf("ttl %v: Deadline = %v, want open time + %v (%v)", tc.ttl, got, tc.want, want)
		}
		if armed, d, _ := h.timers.state(); armed != 1 || d != tc.want {
			t.Fatalf("ttl %v: afterFunc armed %d times with %v, want once with %v", tc.ttl, armed, d, tc.want)
		}
		if !h.w.IsOpen() {
			t.Fatalf("ttl %v: IsOpen = false right after opening", tc.ttl)
		}
	}

	before := time.Now()
	w, err := pairing.OpenWindow(windowPin, 0)
	after := time.Now()
	if err != nil || w == nil {
		t.Fatalf("OpenWindow(pin, 0) = %v, %v", w, err)
	}
	t.Cleanup(w.Close)
	if dl := w.Deadline(); dl.Before(before.Add(2*time.Minute)) || dl.After(after.Add(2*time.Minute)) {
		t.Fatalf("OpenWindow(pin, 0): Deadline %v not open time + 2m [%v, %v]", dl, before, after)
	}
	if !w.IsOpen() {
		t.Fatal("OpenWindow(pin, 0): IsOpen = false right after opening")
	}

	for _, ttl := range []time.Duration{-time.Nanosecond, -time.Minute} {
		w, err := pairing.OpenWindow(windowPin, ttl)
		if !errors.Is(err, pairing.ErrWindowTTL) || w != nil {
			t.Fatalf("OpenWindow(pin, %v) = %v, %v; want nil, ErrWindowTTL", ttl, w, err)
		}
	}

	nc := nonCanonicalPin(t, windowPin)
	for name, pin := range map[string]string{
		"empty":         "",
		"not base64":    "!!!not-a-pin!!!",
		"trailing junk": windowPin + "x",
		"surrounding":   " " + windowPin,
		"non-canonical": nc,
	} {
		w, err := pairing.OpenWindow(pin, 0)
		if err == nil || w != nil {
			t.Fatalf("%s: OpenWindow(%q) = %v, %v; want nil, error", name, pin, w, err)
		}
	}
	if _, err := pairing.OpenWindow(nc, 0); !errors.Is(err, identity.ErrPinNotCanonical) {
		t.Fatalf("non-canonical pin: error %v does not wrap identity.ErrPinNotCanonical", err)
	}
}

func TestWindow_IsOpenFollowsDeadline(t *testing.T) {
	h := openTest(t, time.Minute)
	if !h.w.IsOpen() {
		t.Fatal("IsOpen = false right after opening")
	}
	h.clock.Advance(time.Minute - time.Nanosecond)
	if !h.w.IsOpen() {
		t.Fatal("IsOpen = false 1ns before the deadline")
	}
	h.clock.Advance(time.Nanosecond)
	if h.w.IsOpen() {
		t.Fatal("IsOpen = true at the deadline")
	}
	h.clock.Advance(time.Hour)
	if h.w.IsOpen() {
		t.Fatal("IsOpen = true after the deadline")
	}

	t.Run("timer closes it", func(t *testing.T) {
		h := openTest(t, time.Minute)
		held := h.w.HeldBlob()
		if held.Secret() == zeroKey {
			t.Fatal("held secret is zero while open")
		}
		h.clock.Advance(time.Minute)
		h.timers.fire(t)
		// Nothing but the timer callback ran: the wipe proves it closed the window.
		if held.Secret() != zeroKey {
			t.Fatal("firing the timer past the deadline did not close the window (secret not wiped)")
		}
		if r, ok := waitResult(t, h.w); !ok || r.Reason != pairing.ReasonExpired {
			t.Fatalf("WaitResult after timer = %+v, %v; want ReasonExpired, true", r, ok)
		}
	})

	t.Run("real clock and timer", func(t *testing.T) {
		const ttl = 200 * time.Millisecond
		start := time.Now()
		w, err := pairing.OpenWindow(windowPin, ttl)
		if err != nil {
			t.Fatalf("OpenWindow: %v", err)
		}
		t.Cleanup(w.Close)
		// The deadline must keep its monotonic reading (no UTC/Round/In), so
		// IsOpen is immune to wall-clock jumps.
		if s := w.Deadline().String(); !strings.Contains(s, "m=") {
			t.Fatalf("Deadline %q has no monotonic reading", s)
		}
		if !w.IsOpen() {
			t.Fatal("IsOpen = false right after opening")
		}
		r, ok := waitResult(t, w)
		if !ok || r.Reason != pairing.ReasonExpired {
			t.Fatalf("WaitResult = %+v, %v; want ReasonExpired, true (the real timer must close the window)", r, ok)
		}
		if el := time.Since(start); el < ttl {
			t.Fatalf("window expired after %v, before its %v lifetime", el, ttl)
		}
		if w.IsOpen() {
			t.Fatal("IsOpen = true after expiry")
		}
	})
}

func TestWindow_NilIsClosed(t *testing.T) {
	var w *pairing.Window
	if w.IsOpen() {
		t.Fatal("nil IsOpen = true")
	}
	if b := w.Blob(); b != "" {
		t.Fatalf("nil Blob = %q", b)
	}
	if !w.Deadline().IsZero() {
		t.Fatalf("nil Deadline = %v", w.Deadline())
	}
	st := w.Status()
	if st.Open || st.SourcesTracked != 0 || st.SourcesExhausted != 0 || st.SourceSlotsFree != 0 || !st.Deadline.IsZero() {
		t.Fatalf("nil Status = %+v; want closed with zero counts", st)
	}
	// The nil path still runs an HMAC against a fixed dummy key (spec); that
	// is not observable here because a nil window has no injected verify.
	for _, proof := range [][]byte{badProof, nil} {
		if got := w.Attempt(netip.MustParseAddr("192.0.2.1"), proof, testEKM); got != pairing.StatusWindowClosed {
			t.Fatalf("nil Attempt = %v, want window_closed", got)
		}
	}
}

func TestWindow_BlobOnlyWhileOpen(t *testing.T) {
	h := openTest(t, time.Minute)
	s := h.w.Blob()
	b, err := pairing.ParseBlob(s)
	if err != nil {
		t.Fatalf("ParseBlob(Blob()) while open: %v", err)
	}
	if b.PinB64() != windowPin {
		t.Fatalf("blob pin %q, want the listener pin %q", b.PinB64(), windowPin)
	}
	if again := h.w.Blob(); again != s {
		t.Fatal("Blob changed between two calls while open")
	}
	if held := h.w.HeldBlob(); held.Encode() != s {
		t.Fatal("Blob() is not the encoding of the held blob")
	}

	h.clock.Advance(time.Minute)
	if got := h.w.Blob(); got != "" {
		t.Fatalf("Blob after the deadline = %q, want \"\"", got)
	}

	h = openTest(t, time.Minute)
	if st := h.w.Attempt(netip.MustParseAddr("192.0.2.1"), validProof(t, h.w), testEKM); st != pairing.StatusOK {
		t.Fatalf("valid Attempt = %v", st)
	}
	if got := h.w.Blob(); got != "" {
		t.Fatalf("Blob after success = %q, want \"\"", got)
	}

	h = openTest(t, time.Minute)
	_ = secretOf(t, h.w)
	h.w.Close()
	if got := h.w.Blob(); got != "" {
		t.Fatalf("Blob after Close = %q, want \"\"", got)
	}
}

func TestAttempt_ValidProofClosesBeforeReturning(t *testing.T) {
	h := openTest(t, time.Minute)
	p := validProof(t, h.w)
	h.clock.Advance(10 * time.Second)
	if st := h.w.Attempt(netip.MustParseAddr("192.0.2.1"), p, testEKM); st != pairing.StatusOK {
		t.Fatalf("valid Attempt = %v, want ok", st)
	}
	if h.w.IsOpen() {
		t.Fatal("IsOpen = true after Attempt returned ok")
	}
	if st := h.w.Status(); st.Open {
		t.Fatalf("Status after ok = %+v, want closed", st)
	}
	r, ok := waitResult(t, h.w)
	if !ok || r.Reason != pairing.ReasonPaired || !r.ClosedAt.Equal(h.clock.Now()) {
		t.Fatalf("WaitResult = %+v, %v; want ReasonPaired at %v, true", r, ok, h.clock.Now())
	}
	if st := h.w.Attempt(netip.MustParseAddr("198.51.100.1"), p, testEKM); st != pairing.StatusWindowClosed {
		t.Fatalf("second valid Attempt = %v, want window_closed", st)
	}
}

// Budget boundary, both sides (5 attempts per source). Attempts 1-5
// from one source key are evaluated; attempt 6 and later are rate_limited
// without being honored, even with a valid proof.
func TestAttempt_InvalidProofsUpToBudgetThenRateLimited(t *testing.T) {
	h := openTest(t, time.Minute)
	src := netip.MustParseAddr("192.0.2.7")
	for i := 1; i <= wantBudget; i++ {
		if st := h.w.Attempt(src, badProof, testEKM); st != pairing.StatusBadProof {
			t.Fatalf("bad proof %d of %d = %v, want bad_proof", i, wantBudget, st)
		}
		if !h.w.IsOpen() {
			t.Fatalf("window closed after bad proof %d", i)
		}
	}
	valid := validProof(t, h.w)
	if st := h.w.Attempt(src, valid, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("attempt %d with a VALID proof = %v, want rate_limited", wantBudget+1, st)
	}
	if st := h.w.Attempt(src, badProof, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("attempt %d = %v, want rate_limited", wantBudget+2, st)
	}
	if got := h.vlog.count(); got != wantBudget+2 {
		t.Fatalf("verify ran %d times for %d attempts; it must run on every path", got, wantBudget+2)
	}
	if !h.w.IsOpen() {
		t.Fatal("window closed by one source exhausting its budget")
	}
	if st := h.w.Status(); st.SourcesTracked != 1 || st.SourcesExhausted != 1 {
		t.Fatalf("Status = %+v, want 1 tracked, 1 exhausted", st)
	}
	if st := h.w.Attempt(netip.MustParseAddr("192.0.2.8"), valid, testEKM); st != pairing.StatusOK {
		t.Fatalf("another source with a valid proof = %v, want ok", st)
	}
}

// One source exhausting its budget never closes the window for others.
func TestAttempt_ExhaustedSourceLeavesWindowOpenForOthers(t *testing.T) {
	h := openTest(t, time.Minute)
	dl := h.w.Deadline()
	a := netip.MustParseAddr("192.0.2.10")
	for range wantBudget {
		h.w.Attempt(a, badProof, testEKM)
	}
	if st := h.w.Attempt(a, badProof, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("exhausted source = %v, want rate_limited", st)
	}
	if !h.w.IsOpen() || !h.w.Status().Open || !h.w.Deadline().Equal(dl) {
		t.Fatalf("exhausting one source changed the window: open %v, status %+v, deadline %v (was %v)",
			h.w.IsOpen(), h.w.Status(), h.w.Deadline(), dl)
	}
	b := netip.MustParseAddr("198.51.100.20")
	for i := 1; i <= wantBudget; i++ {
		if st := h.w.Attempt(b, badProof, testEKM); st != pairing.StatusBadProof {
			t.Fatalf("other source, bad proof %d = %v, want bad_proof (its own budget)", i, st)
		}
	}
	if st := h.w.Attempt(netip.MustParseAddr("2001:db8:9::1"), validProof(t, h.w), testEKM); st != pairing.StatusOK {
		t.Fatalf("third source with a valid proof = %v, want ok", st)
	}
	if r, ok := waitResult(t, h.w); !ok || r.Reason != pairing.ReasonPaired {
		t.Fatalf("WaitResult = %+v, %v; want ReasonPaired", r, ok)
	}
}

func TestSourceKey_Table(t *testing.T) {
	ap1 := netip.MustParseAddrPort("192.0.2.7:1000")
	ap2 := netip.MustParseAddrPort("192.0.2.7:2000")
	for _, tc := range []struct {
		name string
		in   netip.Addr
		want string // "" = refused
	}{
		{"ipv4 is /32", netip.MustParseAddr("192.0.2.7"), "192.0.2.7/32"},
		{"ipv4 neighbour is its own /32", netip.MustParseAddr("192.0.2.8"), "192.0.2.8/32"},
		{"port 1000 not in key", ap1.Addr(), "192.0.2.7/32"},
		{"port 2000 not in key", ap2.Addr(), "192.0.2.7/32"},
		{"ipv6 is /64", netip.MustParseAddr("2001:db8:1:2::1"), "2001:db8:1:2::/64"},
		{"ipv6 same /64", netip.MustParseAddr("2001:db8:1:2:ffff:ffff:ffff:ffff"), "2001:db8:1:2::/64"},
		{"ipv6 neighbour /64", netip.MustParseAddr("2001:db8:1:3::1"), "2001:db8:1:3::/64"},
		{"ipv4-mapped is ipv4", netip.MustParseAddr("::ffff:192.0.2.7"), "192.0.2.7/32"},
		{"second ipv4-mapped is its own /32", netip.MustParseAddr("::ffff:192.0.2.8"), "192.0.2.8/32"},
		{"zone dropped", netip.MustParseAddr("fe80::1%eth0"), "fe80::/64"},
		{"invalid refused", netip.Addr{}, ""},
	} {
		got, ok := pairing.SourceKey(tc.in)
		switch {
		case tc.want == "" && ok:
			t.Errorf("%s: SourceKey(%v) = %v, true; want refused", tc.name, tc.in, got)
		case tc.want != "" && (!ok || got.String() != tc.want || got.Addr().Zone() != ""):
			t.Errorf("%s: SourceKey(%v) = %v, %v; want %s", tc.name, tc.in, got, ok, tc.want)
		}
	}

	// The same rules through Attempt.
	h := openTest(t, time.Minute)
	exhaust := func(a netip.Addr) {
		for range wantBudget {
			h.w.Attempt(a, badProof, testEKM)
		}
	}
	exhaust(netip.MustParseAddr("2001:db8:1:2::1"))
	if st := h.w.Attempt(netip.MustParseAddr("2001:db8:1:2::2"), badProof, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("same /64 after exhaustion = %v, want rate_limited", st)
	}
	if st := h.w.Attempt(netip.MustParseAddr("2001:db8:1:3::1"), badProof, testEKM); st != pairing.StatusBadProof {
		t.Fatalf("neighbour /64 = %v, want bad_proof (own budget)", st)
	}
	exhaust(netip.MustParseAddr("192.0.2.7"))
	if st := h.w.Attempt(netip.MustParseAddr("192.0.2.8"), badProof, testEKM); st != pairing.StatusBadProof {
		t.Fatalf("neighbour ipv4 = %v, want bad_proof (own /32)", st)
	}
	tracked := h.w.Status().SourcesTracked
	n := h.vlog.count()
	// Invalid source: refused before any proof check. Serve never passes one,
	// so the timing of this path is not observable to a peer.
	if st := h.w.Attempt(netip.Addr{}, validProof(t, h.w), testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("invalid source = %v, want rate_limited", st)
	}
	if got := h.w.Status().SourcesTracked; got != tracked {
		t.Fatalf("invalid source created a table entry: tracked %d -> %d", tracked, got)
	}
	if got := h.vlog.count(); got != n {
		t.Fatalf("invalid source reached verify (%d -> %d calls)", n, got)
	}
	if !h.w.IsOpen() {
		t.Fatal("invalid source closed the window")
	}
}

// An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d; it must
// share the budget of a.b.c.d.
func TestAttempt_DualStackMappedSourceBudgetedAsIPv4(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:203.0.113.5")
	plain := netip.MustParseAddr("203.0.113.5")
	other := netip.MustParseAddr("::ffff:203.0.113.6")

	h := openTest(t, time.Minute)
	for range 3 {
		h.w.Attempt(mapped, badProof, testEKM)
	}
	for range 2 {
		h.w.Attempt(plain, badProof, testEKM)
	}
	if st := h.w.Attempt(mapped, badProof, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("mapped after 5 failures shared with plain = %v, want rate_limited", st)
	}
	if st := h.w.Attempt(plain, badProof, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("plain after 5 failures shared with mapped = %v, want rate_limited", st)
	}
	if st := h.w.Status(); st.SourcesTracked != 1 {
		t.Fatalf("mapped and plain tracked as %d sources, want 1", st.SourcesTracked)
	}
	if st := h.w.Attempt(other, badProof, testEKM); st != pairing.StatusBadProof {
		t.Fatalf("another mapped ipv4 = %v, want bad_proof (own /32)", st)
	}

	h = openTest(t, time.Minute)
	for range wantBudget {
		h.w.Attempt(plain, badProof, testEKM)
	}
	if st := h.w.Attempt(mapped, validProof(t, h.w), testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("mapped with a valid proof after plain exhausted = %v, want rate_limited", st)
	}
	if st := h.w.Attempt(other, validProof(t, h.w), testEKM); st != pairing.StatusOK {
		t.Fatalf("another mapped ipv4 with a valid proof = %v, want ok", st)
	}
}

// The table holds at most 1024 sources; a new source at the bound is
// refused (even with a valid proof), and nothing is evicted.
func TestAttempt_TableBoundRefusesNewSourcesWithoutEviction(t *testing.T) {
	h := openTest(t, time.Minute)
	for range wantBudget {
		h.w.Attempt(v4(0), badProof, testEKM)
	}
	for i := 1; i < wantBound-1; i++ {
		if st := h.w.Attempt(v4(i), badProof, testEKM); st != pairing.StatusBadProof {
			t.Fatalf("source %d of %d = %v, want bad_proof", i+1, wantBound, st)
		}
	}
	if st := h.w.Status(); st.SourcesTracked != wantBound-1 || st.SourceSlotsFree != 1 {
		t.Fatalf("Status with %d sources = %+v, want 1 slot free", wantBound-1, st)
	}
	if st := h.w.Attempt(v4(wantBound-1), badProof, testEKM); st != pairing.StatusBadProof {
		t.Fatalf("source %d (bound-1 tracked) = %v, want bad_proof (admitted)", wantBound, st)
	}
	if st := h.w.Status(); st.SourcesTracked != wantBound || st.SourceSlotsFree != 0 {
		t.Fatalf("Status at the bound = %+v, want %d tracked, 0 free", st, wantBound)
	}
	valid := validProof(t, h.w)
	if st := h.w.Attempt(v4(wantBound), valid, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("new source at the bound with a VALID proof = %v, want rate_limited", st)
	}
	if st := h.w.Attempt(netip.MustParseAddr("2001:db8:77::1"), valid, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("new ipv6 source at the bound = %v, want rate_limited", st)
	}
	for i := wantBound + 1; i < wantBound+50; i++ {
		if st := h.w.Attempt(v4(i), badProof, testEKM); st != pairing.StatusRateLimited {
			t.Fatalf("new source %d at the bound = %v, want rate_limited", i, st)
		}
	}
	if !h.w.IsOpen() {
		t.Fatal("a full table closed the window")
	}
	if st := h.w.Status(); st.SourcesTracked != wantBound {
		t.Fatalf("refused sources changed the table: tracked %d", st.SourcesTracked)
	}
	// Positive controls: nothing was evicted.
	if st := h.w.Attempt(v4(0), badProof, testEKM); st != pairing.StatusRateLimited {
		t.Fatalf("oldest (exhausted) source = %v, want rate_limited (no eviction, no reset)", st)
	}
	if st := h.w.Attempt(v4(wantBound-1), badProof, testEKM); st != pairing.StatusBadProof {
		t.Fatalf("newest tracked source = %v, want bad_proof (still tracked)", st)
	}
	if st := h.w.Attempt(v4(1), valid, testEKM); st != pairing.StatusOK {
		t.Fatalf("tracked source with budget left and a valid proof on a full table = %v, want ok", st)
	}
}

// Timing indistinguishability: verify runs exactly once on every refusal
// path, and after close it runs against a stand-in key, never the secret
// secret or a zero key (VerifyProof returns early for a zero key).
func TestAttempt_ExpiredWindowStillVerifiesProof(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.30")
	check := func(t *testing.T, h *winHarness, n int, p []byte, wantClosed bool, secret [pairing.SecretLen]byte) {
		t.Helper()
		if got := h.vlog.count(); got != n+1 {
			t.Fatalf("verify ran %d times for one Attempt, want exactly 1", got-n)
		}
		key, ln, ekm, got := h.vlog.last(t)
		if ln != pairing.SecretLen {
			t.Fatalf("verify key length %d, want %d", ln, pairing.SecretLen)
		}
		if !bytes.Equal(ekm, testEKM) || !bytes.Equal(got, p) {
			t.Fatal("verify did not receive the attempt's ekm and proof")
		}
		switch {
		case wantClosed && key == secret:
			t.Fatal("closed window verified against the real secret")
		case wantClosed && key == zeroKey:
			t.Fatal("closed window verified against a zero key")
		case !wantClosed && key != secret:
			t.Fatal("open window did not verify against the real secret")
		}
	}
	closers := map[string]func(h *winHarness, secret [pairing.SecretLen]byte){
		"expired": func(h *winHarness, _ [pairing.SecretLen]byte) { h.clock.Advance(time.Minute) },
		"paired": func(h *winHarness, secret [pairing.SecretLen]byte) {
			h.w.Attempt(netip.MustParseAddr("198.51.100.1"), pairing.Proof(secret[:], testEKM), testEKM)
		},
		"closed": func(h *winHarness, _ [pairing.SecretLen]byte) { h.w.Close() },
	}
	for name, closeIt := range closers {
		t.Run(name, func(t *testing.T) {
			h := openTest(t, time.Minute)
			secret := secretOf(t, h.w)
			p := pairing.Proof(secret[:], testEKM)
			closeIt(h, secret)
			for i := range 2 {
				n := h.vlog.count()
				if st := h.w.Attempt(src, p, testEKM); st != pairing.StatusWindowClosed {
					t.Fatalf("attempt %d after close with the real proof = %v, want window_closed", i+1, st)
				}
				check(t, h, n, p, true, secret)
			}
		})
	}
	t.Run("rate-limited source", func(t *testing.T) {
		h := openTest(t, time.Minute)
		secret := secretOf(t, h.w)
		for range wantBudget {
			h.w.Attempt(src, badProof, testEKM)
		}
		p := pairing.Proof(secret[:], testEKM)
		n := h.vlog.count()
		if st := h.w.Attempt(src, p, testEKM); st != pairing.StatusRateLimited {
			t.Fatalf("exhausted source = %v, want rate_limited", st)
		}
		check(t, h, n, p, false, secret)
	})
	t.Run("table full", func(t *testing.T) {
		h := openTest(t, time.Minute)
		secret := secretOf(t, h.w)
		for i := range wantBound {
			h.w.Attempt(v4(i), badProof, testEKM)
		}
		p := pairing.Proof(secret[:], testEKM)
		n := h.vlog.count()
		if st := h.w.Attempt(v4(wantBound), p, testEKM); st != pairing.StatusRateLimited {
			t.Fatalf("new source on a full table = %v, want rate_limited", st)
		}
		check(t, h, n, p, false, secret)
	})
}

// within runs f and fails if it does not return in 5 s.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return within 5s", what)
	}
}

// Every close wipes the real secret in place; later attempts verify
// against a stand-in key read from opts.rand.
func TestWindow_SecretWipedOnEveryClose(t *testing.T) {
	late := netip.MustParseAddr("192.0.2.40")
	lateKey := func(t *testing.T, h *winHarness, secret [pairing.SecretLen]byte) [pairing.SecretLen]byte {
		t.Helper()
		if st := h.w.Attempt(late, pairing.Proof(secret[:], testEKM), testEKM); st != pairing.StatusWindowClosed {
			t.Fatalf("attempt after close = %v, want window_closed", st)
		}
		key, n, _, _ := h.vlog.last(t)
		if n != pairing.SecretLen {
			t.Fatalf("stand-in key length %d, want %d", n, pairing.SecretLen)
		}
		if key == secret {
			t.Fatal("attempt after close verified against the real secret")
		}
		if key == zeroKey {
			t.Fatal("attempt after close verified against a zero key")
		}
		return key
	}
	// open returns a window and a Blob copy sharing its secret array.
	open := func(t *testing.T, mods ...func(*pairing.WindowOpts)) (*winHarness, pairing.Blob, [pairing.SecretLen]byte) {
		t.Helper()
		h := openTest(t, time.Minute, mods...)
		held := h.w.HeldBlob()
		secret := secretOf(t, h.w)
		if secret == zeroKey || held.Secret() != secret {
			t.Fatal("the held blob does not carry the window's secret")
		}
		return h, held, secret
	}

	closers := map[string]func(t *testing.T, h *winHarness, secret [pairing.SecretLen]byte){
		"paired": func(t *testing.T, h *winHarness, secret [pairing.SecretLen]byte) {
			if st := h.w.Attempt(netip.MustParseAddr("198.51.100.1"), pairing.Proof(secret[:], testEKM), testEKM); st != pairing.StatusOK {
				t.Fatalf("valid Attempt = %v, want ok", st)
			}
		},
		"expired, noticed by Attempt": func(t *testing.T, h *winHarness, _ [pairing.SecretLen]byte) {
			h.clock.Advance(time.Minute)
			if st := h.w.Attempt(netip.MustParseAddr("198.51.100.1"), badProof, testEKM); st != pairing.StatusWindowClosed {
				t.Fatalf("Attempt after the deadline = %v, want window_closed", st)
			}
		},
		"expired by the timer": func(t *testing.T, h *winHarness, _ [pairing.SecretLen]byte) {
			h.clock.Advance(time.Minute)
			h.timers.fire(t)
		},
		"Close": func(t *testing.T, h *winHarness, _ [pairing.SecretLen]byte) { h.w.Close() },
	}
	for name, closeIt := range closers {
		t.Run(name, func(t *testing.T) {
			h, held, secret := open(t)
			closeIt(t, h, secret)
			if held.Secret() != zeroKey {
				t.Fatal("the real secret was not wiped in place on close")
			}
			if b := h.w.Blob(); b != "" {
				t.Fatalf("Blob after close = %q", b)
			}
			if key := lateKey(t, h, secret); key != patternKey(standInSeed) {
				t.Fatalf("stand-in key %x, want the 16 bytes read from opts.rand %x", key, patternKey(standInSeed))
			}
		})
	}

	t.Run("all-zero rand", func(t *testing.T) {
		h, held, secret := open(t, func(o *pairing.WindowOpts) { o.Rand = zeroReader{} })
		within(t, "Close with an all-zero rand", h.w.Close)
		if held.Secret() != zeroKey {
			t.Fatal("the real secret was not wiped")
		}
		lateKey(t, h, secret)
	})
	t.Run("failing rand", func(t *testing.T) {
		h, held, secret := open(t, func(o *pairing.WindowOpts) { o.Rand = failReader{} })
		within(t, "Close with a failing rand", h.w.Close)
		if h.w.IsOpen() {
			t.Fatal("window still open after Close with a failing rand")
		}
		if r, ok := waitResult(t, h.w); !ok || r.Reason != pairing.ReasonClosed {
			t.Fatalf("WaitResult = %+v, %v; want ReasonClosed", r, ok)
		}
		if held.Secret() != zeroKey {
			t.Fatal("the real secret was not wiped")
		}
		lateKey(t, h, secret)
	})
	t.Run("Blob racing Close never encodes a wiped secret", func(t *testing.T) {
		// The next clock read after arming blocks, so Blob is held between
		// its open check and encoding while Close is started. -race cannot
		// see this: it does not instrument clear() on the secret.
		var armed atomic.Bool
		entered, gate := make(chan struct{}), make(chan struct{})
		var once sync.Once
		releaseClock := func() { once.Do(func() { close(gate) }) }
		t.Cleanup(releaseClock)
		h := openTest(t, time.Minute, func(o *pairing.WindowOpts) {
			now := o.Now
			o.Now = func() time.Time {
				if armed.CompareAndSwap(true, false) {
					close(entered)
					<-gate
				}
				return now()
			}
		})
		armed.Store(true)
		blob := make(chan string, 1)
		go func() { blob <- h.w.Blob() }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("Blob never read the clock")
		}
		closed := make(chan struct{})
		go func() { defer close(closed); h.w.Close() }()
		select {
		case <-closed:
		case <-time.After(100 * time.Millisecond):
		}
		releaseClock()
		var got string
		select {
		case got = <-blob:
		case <-time.After(5 * time.Second):
			t.Fatal("Blob did not return")
		}
		within(t, "Close", func() { <-closed })
		if got == "" {
			return // Blob saw the window closed: nothing encoded
		}
		if _, err := pairing.ParseBlob(got); err != nil {
			t.Errorf("Blob racing Close returned %q, which does not parse: %v (a wiped secret was encoded)", got, err)
		}
	})
	t.Run("crypto/rand stand-ins differ", func(t *testing.T) {
		var keys [2][pairing.SecretLen]byte
		for i := range keys {
			h, _, secret := open(t, func(o *pairing.WindowOpts) { o.Rand = nil })
			h.w.Close()
			keys[i] = lateKey(t, h, secret)
		}
		if keys[0] == keys[1] {
			t.Fatalf("two windows closed with the same stand-in key %x; it must be random", keys[0])
		}
	})
}

func TestAttempt_ConcurrentValidProofsSingleSuccess(t *testing.T) {
	leakCheck(t)
	h := openTest(t, time.Minute)
	p := validProof(t, h.w)
	const n = 32
	start := make(chan struct{})
	results := make([]pairing.Status, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			results[i] = h.w.Attempt(v4(i), p, testEKM)
		})
	}
	close(start)
	wg.Wait()
	counts := map[pairing.Status]int{}
	for _, st := range results {
		counts[st]++
	}
	if counts[pairing.StatusOK] != 1 || counts[pairing.StatusWindowClosed] != n-1 {
		t.Fatalf("%d concurrent valid proofs: %v; want exactly 1 ok and %d window_closed", n, counts, n-1)
	}
	if r, ok := waitResult(t, h.w); !ok || r.Reason != pairing.ReasonPaired {
		t.Fatalf("WaitResult = %+v, %v; want ReasonPaired", r, ok)
	}
}

func recvStatus(t *testing.T, what string, c <-chan pairing.Status) pairing.Status {
	t.Helper()
	select {
	case st := <-c:
		return st
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return within 5s", what)
		return 0
	}
}

// One critical section spans check-open -> budget -> verify -> close.
func TestAttempt_LockSpansVerify(t *testing.T) {
	leakCheck(t)
	h := openTest(t, time.Minute)
	release := h.gated(t)
	p := validProof(t, h.w)
	first := make(chan pairing.Status, 1)
	second := make(chan pairing.Status, 1)
	go func() { first <- h.w.Attempt(netip.MustParseAddr("192.0.2.50"), p, testEKM) }()
	h.waitEntered(t)
	go func() { second <- h.w.Attempt(netip.MustParseAddr("192.0.2.51"), p, testEKM) }()
	select {
	case st := <-second:
		t.Fatalf("an Attempt returned %v while another Attempt of the same window was inside verify", st)
	case <-time.After(200 * time.Millisecond):
	}
	if c := h.vlog.count(); c != 1 {
		t.Fatalf("verify ran %d times while the first Attempt held the window; want 1", c)
	}
	release()
	if st := recvStatus(t, "first Attempt", first); st != pairing.StatusOK {
		t.Fatalf("first valid Attempt = %v, want ok", st)
	}
	if st := recvStatus(t, "second Attempt", second); st != pairing.StatusWindowClosed {
		t.Fatalf("second valid Attempt = %v, want window_closed", st)
	}
}

func TestWindows_LocksArePerWindow(t *testing.T) {
	leakCheck(t)
	a := openTest(t, time.Minute)
	release := a.gated(t)
	pa := validProof(t, a.w)
	b := openTest(t, time.Minute)
	pb := validProof(t, b.w)
	resA := make(chan pairing.Status, 1)
	go func() { resA <- a.w.Attempt(netip.MustParseAddr("192.0.2.60"), pa, testEKM) }()
	a.waitEntered(t)
	resB := make(chan pairing.Status, 1)
	go func() { resB <- b.w.Attempt(netip.MustParseAddr("192.0.2.61"), pb, testEKM) }()
	select {
	case st := <-resB:
		if st != pairing.StatusOK {
			t.Fatalf("window B Attempt = %v, want ok", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("window B blocked while window A was inside verify: windows share a lock")
	}
	release()
	if st := recvStatus(t, "window A Attempt", resA); st != pairing.StatusOK {
		t.Fatalf("window A Attempt = %v, want ok", st)
	}
}

// IsOpen is lock-free; it answers while an Attempt holds the lock.
func TestWindow_IsOpenDoesNotBlockDuringAttempt(t *testing.T) {
	leakCheck(t)
	h := openTest(t, time.Minute)
	release := h.gated(t)
	p := validProof(t, h.w)
	attempt := make(chan pairing.Status, 1)
	go func() { attempt <- h.w.Attempt(netip.MustParseAddr("192.0.2.70"), p, testEKM) }()
	h.waitEntered(t)
	isOpen := make(chan bool, 1)
	go func() { isOpen <- h.w.IsOpen() }()
	select {
	case open := <-isOpen:
		if !open {
			t.Fatal("IsOpen = false while the window is open")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IsOpen blocked while an Attempt held the window lock")
	}
	// Positive control: the Attempt really was still inside verify.
	select {
	case st := <-attempt:
		t.Fatalf("control: Attempt returned %v before verify was released", st)
	default:
	}
	release()
	if st := recvStatus(t, "Attempt", attempt); st != pairing.StatusOK {
		t.Fatalf("Attempt = %v, want ok", st)
	}
	if h.w.IsOpen() {
		t.Fatal("IsOpen = true after success")
	}
}

type waitOutcome struct {
	r  pairing.Result
	ok bool
}

func TestWaitResult_EndsOnSuccessExpiryCloseOrContext(t *testing.T) {
	leakCheck(t)
	start := func(t *testing.T, w *pairing.Window, ctx context.Context) <-chan waitOutcome {
		t.Helper()
		c := make(chan waitOutcome, 1)
		go func() {
			r, ok := w.WaitResult(ctx)
			c <- waitOutcome{r, ok}
		}()
		select {
		case o := <-c:
			t.Fatalf("WaitResult returned %+v before the window closed or ctx ended", o)
		case <-time.After(50 * time.Millisecond):
		}
		return c
	}
	recv := func(t *testing.T, c <-chan waitOutcome) waitOutcome {
		t.Helper()
		select {
		case o := <-c:
			return o
		case <-time.After(5 * time.Second):
			t.Fatal("WaitResult did not return within 5s")
			return waitOutcome{}
		}
	}
	for _, tc := range []struct {
		name    string
		reason  pairing.CloseReason
		trigger func(t *testing.T, h *winHarness)
	}{
		{"success", pairing.ReasonPaired, func(t *testing.T, h *winHarness) {
			h.w.Attempt(netip.MustParseAddr("192.0.2.80"), validProof(t, h.w), testEKM)
		}},
		{"expiry", pairing.ReasonExpired, func(t *testing.T, h *winHarness) {
			h.clock.Advance(time.Minute)
			h.timers.fire(t)
		}},
		{"Close", pairing.ReasonClosed, func(t *testing.T, h *winHarness) { h.w.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := openTest(t, time.Minute)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			c := start(t, h.w, ctx)
			h.clock.Advance(time.Second)
			tc.trigger(t, h)
			closedAt := h.clock.Now()
			o := recv(t, c)
			if !o.ok || o.r.Reason != tc.reason || !o.r.ClosedAt.Equal(closedAt) {
				t.Fatalf("WaitResult = %+v, %v; want reason %v at %v, true", o.r, o.ok, tc.reason, closedAt)
			}
			// The first close is final: a later Close or timer changes nothing.
			h.clock.Advance(time.Hour)
			h.w.Close()
			h.timers.fire(t)
			if r, ok := waitResult(t, h.w); !ok || r != o.r {
				t.Fatalf("WaitResult after a later Close/timer = %+v, %v; want %+v", r, ok, o.r)
			}
		})
	}
	t.Run("context", func(t *testing.T) {
		h := openTest(t, time.Minute)
		ctx, cancel := context.WithCancel(context.Background())
		c := start(t, h.w, ctx)
		cancel()
		if o := recv(t, c); o.ok {
			t.Fatalf("WaitResult after ctx cancel = %+v, true; want false", o.r)
		}
		if !h.w.IsOpen() {
			t.Fatal("cancelling WaitResult's ctx closed the window")
		}
	})
}

func TestWindow_StatusReportsSourceCapacity(t *testing.T) {
	typ := reflect.TypeOf(pairing.WindowStatus{})
	var names []string
	for i := range typ.NumField() {
		names = append(names, typ.Field(i).Name)
	}
	sort.Strings(names)
	if got, want := strings.Join(names, ","), "Deadline,Open,PerSourceBudget,SourceSlotsFree,SourcesExhausted,SourcesTracked"; got != want {
		t.Fatalf("WindowStatus fields %s, want %s (window-wide numbers only, no Budget field)", got, want)
	}

	expect := func(t *testing.T, st pairing.WindowStatus, open bool, dl time.Time, tracked, exhausted, free int) {
		t.Helper()
		if st.Open != open || !st.Deadline.Equal(dl) || st.SourcesTracked != tracked || st.SourcesExhausted != exhausted || st.SourceSlotsFree != free {
			t.Fatalf("Status = %+v; want open %v, deadline %v, tracked %d, exhausted %d, free %d", st, open, dl, tracked, exhausted, free)
		}
		if open && st.PerSourceBudget != wantBudget {
			t.Fatalf("PerSourceBudget = %d, want %d", st.PerSourceBudget, wantBudget)
		}
	}

	h := openTest(t, time.Minute)
	dl := h.w.Deadline()
	if dl.IsZero() {
		t.Fatal("Deadline is zero while open")
	}
	expect(t, h.w.Status(), true, dl, 0, 0, wantBound)
	h.w.Attempt(netip.MustParseAddr("192.0.2.90"), badProof, testEKM)
	b := netip.MustParseAddr("2001:db8:90::1")
	for range wantBudget {
		h.w.Attempt(b, badProof, testEKM)
	}
	expect(t, h.w.Status(), true, dl, 2, 1, wantBound-2)
	h.w.Attempt(b, badProof, testEKM)
	h.w.Attempt(netip.Addr{}, badProof, testEKM)
	expect(t, h.w.Status(), true, dl, 2, 1, wantBound-2)

	// Closed (expired, noticed by Status itself): open false, zero counts.
	h.clock.Advance(time.Minute)
	if st := h.w.Status(); st.Open || st.SourcesTracked != 0 || st.SourcesExhausted != 0 || st.SourceSlotsFree != 0 {
		t.Fatalf("Status after expiry = %+v; want closed with zero counts", st)
	}
	h = openTest(t, time.Minute)
	h.w.Attempt(netip.MustParseAddr("192.0.2.91"), badProof, testEKM)
	h.w.Close()
	if st := h.w.Status(); st.Open || st.SourcesTracked != 0 || st.SourcesExhausted != 0 || st.SourceSlotsFree != 0 {
		t.Fatalf("Status after Close = %+v; want closed with zero counts", st)
	}
}

// Not parallel: goleak.VerifyNone sees every goroutine in the binary.
func TestWindow_NoGoroutineOutlivesWindow(t *testing.T) {
	// The timer is stopped on every close other than its own firing, exactly
	// once. An unstopped AfterFunc timer is not a goroutine until it fires,
	// so goleak alone cannot see it.
	for name, closeIt := range map[string]func(t *testing.T, h *winHarness){
		"success": func(t *testing.T, h *winHarness) {
			h.w.Attempt(netip.MustParseAddr("192.0.2.100"), validProof(t, h.w), testEKM)
		},
		"Close": func(t *testing.T, h *winHarness) { h.w.Close() },
		"expired, noticed by Attempt": func(t *testing.T, h *winHarness) {
			h.clock.Advance(time.Minute)
			h.w.Attempt(netip.MustParseAddr("192.0.2.100"), badProof, testEKM)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := openTest(t, time.Minute)
			closeIt(t, h)
			h.w.Close()
			h.w.Close()
			if _, _, stops := h.timers.state(); stops != 1 {
				t.Fatalf("timer stopped %d times, want exactly once", stops)
			}
		})
	}

	// Real timers.
	w1, err := pairing.OpenWindow(windowPin, time.Minute)
	if err != nil {
		t.Fatalf("OpenWindow: %v", err)
	}
	s := secretOf(t, w1)
	if st := w1.Attempt(netip.MustParseAddr("192.0.2.101"), pairing.Proof(s[:], testEKM), testEKM); st != pairing.StatusOK {
		t.Fatalf("valid Attempt = %v", st)
	}
	w2, err := pairing.OpenWindow(windowPin, time.Minute)
	if err != nil {
		t.Fatalf("OpenWindow: %v", err)
	}
	w2.Close()
	w3, err := pairing.OpenWindow(windowPin, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("OpenWindow: %v", err)
	}
	if r, ok := waitResult(t, w3); !ok || r.Reason != pairing.ReasonExpired {
		t.Fatalf("short window WaitResult = %+v, %v; want ReasonExpired", r, ok)
	}
	w4, err := pairing.OpenWindow(windowPin, time.Millisecond)
	if err != nil {
		t.Fatalf("OpenWindow: %v", err)
	}
	go w4.Close() // races the timer; exactly one close wins
	if _, ok := waitResult(t, w4); !ok {
		t.Fatal("racing Close and timer: WaitResult did not report a close")
	}
	for _, w := range []*pairing.Window{w1, w2, w3, w4} {
		if _, ok := waitResult(t, w); !ok {
			t.Fatal("window not closed")
		}
	}
	goleak.VerifyNone(t)
}
