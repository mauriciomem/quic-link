package pairing

import (
	"io"
	"net/netip"
	"time"
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

// SourceKey exposes sourceKey.
func SourceKey(a netip.Addr) (netip.Prefix, bool) { return sourceKey(a) }

// HeldBlob returns the Blob value the window holds. The copy shares the
// window's secret array, so it observes the wipe at close.
func (w *Window) HeldBlob() Blob { return w.blob }
