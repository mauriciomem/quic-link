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
type Window struct {
	mu     sync.Mutex
	closed atomic.Bool
	blob   Blob
	opts   windowOpts
}

// OpenWindow opens a window for the listener whose pin is listenerPin.
// A ttl of 0 means DefaultWindowTTL.
func OpenWindow(listenerPin string, ttl time.Duration) (*Window, error) {
	return openWindowWith(listenerPin, ttl, defaultOpts())
}

// openWindowWith is OpenWindow with injectable dependencies.
func openWindowWith(listenerPin string, ttl time.Duration, o windowOpts) (*Window, error) {
	// TODO(red stub): not implemented.
	return &Window{opts: o}, nil
}

// IsOpen reports whether the window accepts proofs.
func (w *Window) IsOpen() bool { return false }

// Blob returns the encoded join blob while the window is open, "" otherwise.
func (w *Window) Blob() string { return "" }

// Deadline returns the window's deadline; zero for nil.
func (w *Window) Deadline() time.Time { return time.Time{} }

// Attempt checks one pairing proof from src.
func (w *Window) Attempt(src netip.Addr, proof, ekm []byte) Status { return 0 }

// WaitResult waits for the window to close; false iff ctx ended first.
func (w *Window) WaitResult(ctx context.Context) (Result, bool) { return Result{}, false }

// Close closes the window as ReasonClosed if it is still open.
func (w *Window) Close() {}

// Status reports the window's state.
func (w *Window) Status() WindowStatus { return WindowStatus{} }

// sourceKey returns the budget key of a: the unmapped address's /32 (IPv4) or
// /64 (IPv6).
func sourceKey(a netip.Addr) (netip.Prefix, bool) { return netip.Prefix{}, false }
