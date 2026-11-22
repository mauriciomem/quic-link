package pairing

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultWindowTTL is the lifetime of a pairing window opened with ttl 0.
const DefaultWindowTTL = 2 * time.Minute

const (
	// perSourceBudget is the number of failed proofs allowed per source key.
	perSourceBudget = 5
	// sourceTableBound is the most source keys one window tracks.
	sourceTableBound = 1024
)

// ErrWindowTTL is returned by OpenWindow for a negative lifetime.
var ErrWindowTTL = errors.New("pairing: window lifetime must not be negative")

// CloseReason says why a window closed.
type CloseReason int

// Window close reasons.
const (
	ReasonPaired  CloseReason = iota + 1 // a valid proof closed it
	ReasonExpired                        // the deadline passed
	ReasonClosed                         // Close was called
)

// Result is how a window ended.
type Result struct {
	Reason   CloseReason
	ClosedAt time.Time
}

// WindowStatus describes a window for its operator. There is no window-wide
// attempt budget: budgets are per source. SourceSlotsFree is the number of new
// sources the window can still admit before it refuses every new source.
type WindowStatus struct {
	Open             bool
	Deadline         time.Time
	PerSourceBudget  int // failed proofs allowed per source (IPv4 /32, IPv6 /64)
	SourcesTracked   int
	SourcesExhausted int // sources currently answered rate_limited
	SourceSlotsFree  int // bound - SourcesTracked; 0 means new sources are refused
}

// stopper is the part of *time.Timer a window uses.
type stopper interface{ Stop() bool }

// windowOpts are the window's injectable dependencies.
type windowOpts struct {
	now       func() time.Time
	afterFunc func(time.Duration, func()) stopper
	rand      io.Reader
	verify    func(secret, ekm, got []byte) bool
	budget    int
	bound     int
}

// defaultOpts returns the production dependencies. It is a function, not a
// package variable, so tests build their own opts without shared state.
func defaultOpts() windowOpts {
	return windowOpts{
		now:       time.Now,
		afterFunc: func(d time.Duration, f func()) stopper { return time.AfterFunc(d, f) },
		rand:      rand.Reader,
		verify:    func(s, e, g []byte) bool { return VerifyProof(s, e, g) },
		budget:    perSourceBudget,
		bound:     sourceTableBound,
	}
}

// Window is one pairing window: a one-time secret, a deadline and the
// per-source attempt table. Each Window has its own lock; windows never
// serialize each other. A nil *Window is a closed window.
//
// A Window holds the join secret: never format or log one.
type Window struct {
	// closed and deadline are read without the lock by IsOpen; deadline and
	// opts are immutable after OpenWindow returns.
	closed   atomic.Bool
	deadline time.Time
	opts     windowOpts
	done     chan struct{} // closed by the close transition

	mu      sync.Mutex
	blob    Blob
	standIn [SecretLen]byte // HMAC key for attempts after close
	sources map[netip.Prefix]int
	result  Result
	timer   stopper
}

// fallbackStandIn is the stand-in key when opts.rand fails or yields zeros.
// It must be non-zero: VerifyProof returns early for a zero key, which would
// make a closed window answer faster than an open one.
const fallbackStandIn = "pairing-standin!"

// OpenWindow opens a window for the listener whose pin is listenerPin.
// A ttl of 0 means DefaultWindowTTL.
func OpenWindow(listenerPin string, ttl time.Duration) (*Window, error) {
	return openWindowWith(listenerPin, ttl, defaultOpts())
}

// openWindowWith is OpenWindow with injectable dependencies.
func openWindowWith(listenerPin string, ttl time.Duration, o windowOpts) (*Window, error) {
	if ttl < 0 {
		return nil, ErrWindowTTL
	}
	if ttl == 0 {
		ttl = DefaultWindowTTL
	}
	b, err := NewBlob(listenerPin)
	if err != nil {
		return nil, err
	}
	w := &Window{
		// now() keeps its monotonic reading, so IsOpen ignores wall-clock jumps.
		deadline: o.now().Add(ttl),
		opts:     o,
		done:     make(chan struct{}),
		blob:     b,
		sources:  make(map[netip.Prefix]int),
	}
	// Held so a timer firing at once cannot run before w.timer is set.
	w.mu.Lock()
	w.timer = o.afterFunc(ttl, w.expire)
	w.mu.Unlock()
	return w, nil
}

// IsOpen reports whether the window accepts proofs. It never takes the lock.
func (w *Window) IsOpen() bool {
	return w != nil && !w.closed.Load() && w.opts.now().Before(w.deadline)
}

// Blob returns the encoded join blob while the window is open, "" otherwise.
func (w *Window) Blob() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.openLocked() {
		return ""
	}
	return w.blob.Encode()
}

// Deadline returns the window's deadline; zero for nil.
func (w *Window) Deadline() time.Time {
	if w == nil {
		return time.Time{}
	}
	return w.deadline
}

// Attempt checks one pairing proof from src. The proof is verified exactly
// once on every path that reaches the window - open, closed, rate limited or
// table full - so the answer's timing does not tell them apart. One critical
// section spans check-open, check-budget, verify and mark-closed.
func (w *Window) Attempt(src netip.Addr, proof, ekm []byte) Status {
	if w == nil {
		// No injected verify here; the fixed key keeps the HMAC cost.
		VerifyProof([]byte(fallbackStandIn), ekm, proof)
		return StatusWindowClosed
	}
	key, ok := sourceKey(src)
	if !ok {
		// Fail closed without verifying: Serve never passes an invalid
		// address, so this path's timing is not observable to a peer.
		return StatusRateLimited
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	open := w.openLocked()
	hmacKey := w.standIn[:]
	if open {
		hmacKey = w.blob.secret()[:]
	}
	valid := w.opts.verify(hmacKey, ekm, proof)

	if !open {
		return StatusWindowClosed
	}
	failures, tracked := w.sources[key]
	if !tracked && len(w.sources) >= w.opts.bound {
		return StatusRateLimited // the table is full; nothing is evicted
	}
	if failures >= w.opts.budget {
		return StatusRateLimited
	}
	if valid {
		w.closeLocked(ReasonPaired, true)
		return StatusOK
	}
	w.sources[key] = failures + 1
	return StatusBadProof
}

// WaitResult waits for the window to close; false iff ctx ended first.
func (w *Window) WaitResult(ctx context.Context) (Result, bool) {
	if w == nil {
		return Result{}, false
	}
	w.mu.Lock()
	w.openLocked()
	w.mu.Unlock()
	select {
	case <-w.done:
		return w.lockedResult(), true
	default:
	}
	select {
	case <-w.done:
		return w.lockedResult(), true
	case <-ctx.Done():
		return Result{}, false
	}
}

func (w *Window) lockedResult() Result {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.result
}

// Close closes the window as ReasonClosed if it is still open.
func (w *Window) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed.Load() {
		w.closeLocked(ReasonClosed, true)
	}
}

// Status reports the window's state. A closed window reports zero counts:
// its source table is discarded at close.
func (w *Window) Status() WindowStatus {
	if w == nil {
		return WindowStatus{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.openLocked() {
		return WindowStatus{}
	}
	exhausted := 0
	for _, f := range w.sources {
		if f >= w.opts.budget {
			exhausted++
		}
	}
	return WindowStatus{
		Open:             true,
		Deadline:         w.deadline,
		PerSourceBudget:  w.opts.budget,
		SourcesTracked:   len(w.sources),
		SourcesExhausted: exhausted,
		SourceSlotsFree:  w.opts.bound - len(w.sources),
	}
}

// expire is the timer callback. It closes the window as ReasonExpired once
// the deadline has passed, and re-arms if it fired early.
func (w *Window) expire() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return
	}
	if now := w.opts.now(); now.Before(w.deadline) {
		w.timer = w.opts.afterFunc(w.deadline.Sub(now), w.expire)
		return
	}
	w.closeLocked(ReasonExpired, false)
}

// openLocked reports whether the window is open, closing it as
// ReasonExpired if its deadline has passed. w.mu must be held.
func (w *Window) openLocked() bool {
	if w.closed.Load() {
		return false
	}
	if !w.opts.now().Before(w.deadline) {
		w.closeLocked(ReasonExpired, true)
		return false
	}
	return true
}

// closeLocked is the one transition out of open. w.mu must be held and the
// window open. stopTimer is false only for the timer's own firing.
func (w *Window) closeLocked(reason CloseReason, stopTimer bool) {
	w.closed.Store(true)
	// Wipe in place: every copy of the Blob shares this array. The encoded
	// strings handed out by Blob() cannot be wiped (best effort).
	clear(w.blob.secret()[:])
	w.fillStandIn()
	if stopTimer {
		w.timer.Stop()
	}
	w.result = Result{Reason: reason, ClosedAt: w.opts.now()}
	w.sources = nil
	close(w.done)
}

// fillStandIn reads the stand-in key once; on failure or an all-zero read it
// uses the fixed non-zero fallback rather than retrying.
func (w *Window) fillStandIn() {
	if _, err := io.ReadFull(w.opts.rand, w.standIn[:]); err != nil || w.standIn == [SecretLen]byte{} {
		copy(w.standIn[:], fallbackStandIn)
	}
}

// sourceKey returns the budget key of a: the unmapped address's /32 (IPv4) or
// /64 (IPv6). Unmapping first keeps an IPv4 client on a dual-stack socket in
// its own /32 instead of the shared ::/64; Prefix drops any zone.
func sourceKey(a netip.Addr) (netip.Prefix, bool) {
	a = a.Unmap()
	if !a.IsValid() {
		return netip.Prefix{}, false
	}
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, err := a.Prefix(bits)
	return p, err == nil
}
