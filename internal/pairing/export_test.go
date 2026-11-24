package pairing

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Test-only access to the window's unexported seams for the black-box tests
// in package pairing_test.

// Stopper is the part of *time.Timer a window uses.
type Stopper = stopper

// WindowOpts overrides window dependencies; a nil field keeps the default.
type WindowOpts struct {
	Now       func() time.Time
	AfterFunc func(time.Duration, func()) Stopper
	Rand      io.Reader
	Verify    func(secret, ekm, got []byte) bool
}

// OpenWindowWith is OpenWindow with the given dependencies.
func OpenWindowWith(listenerPin string, ttl time.Duration, o WindowOpts) (*Window, error) {
	d := defaultOpts()
	if o.Now != nil {
		d.now = o.Now
	}
	if o.AfterFunc != nil {
		d.afterFunc = o.AfterFunc
	}
	if o.Rand != nil {
		d.rand = o.Rand
	}
	if o.Verify != nil {
		d.verify = o.Verify
	}
	return openWindowWith(listenerPin, ttl, d)
}

// ServeWithDeadline is Serve with the stream, frame and linger deadline set
// to d instead of the default.
func ServeWithDeadline(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger, d time.Duration) error {
	o := defaultServeOpts()
	o.deadline = d
	return serveWith(ctx, conn, w, p, log, o)
}

// DefaultServeRefusalLinger is how long Serve waits for a refused peer to
// hang up.
func DefaultServeRefusalLinger() time.Duration { return defaultServeOpts().refusalLinger }

// ServeWithShutdownHook is Serve with onShutdown run by the shutdown watcher
// once ctx ended, before the watcher acts; blocking in it holds the watcher.
func ServeWithShutdownHook(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger, onShutdown func()) error {
	o := defaultServeOpts()
	o.onShutdown = onShutdown
	return serveWith(ctx, conn, w, p, log, o)
}

// ServeWithCommitHook is Serve with beforeCommit run on the main path once
// the request was judged ok, just before the commit point takes its lock;
// blocking in it holds the main path there.
func ServeWithCommitHook(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger, beforeCommit func()) error {
	o := defaultServeOpts()
	o.beforeCommit = beforeCommit
	return serveWith(ctx, conn, w, p, log, o)
}

// NewRoutedListenerWithReleaseHook is NewRoutedListener with released run
// after each handler's counts were released.
func NewRoutedListenerWithReleaseHook(ln transport.Listener, handle func(context.Context, transport.Conn), released func()) transport.Listener {
	return newRoutedListener(ln, handle, routeOpts{released: released})
}

// DefaultServeDeadline is the deadline Serve uses.
func DefaultServeDeadline() time.Duration { return defaultServeOpts().deadline }

// SourceKey exposes sourceKey.
func SourceKey(a netip.Addr) (netip.Prefix, bool) { return sourceKey(a) }

// HeldBlob returns the Blob value the window holds. The copy shares the
// window's secret array, so it observes the wipe at close.
func (w *Window) HeldBlob() Blob { return w.blob }
