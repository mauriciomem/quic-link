package pairing

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Persister records a pin admitted by a pairing window.
type Persister interface {
	Persist(pin, label string, from netip.AddrPort) error
}

// Confirmer is optional: a Persister that implements it is told after the ok
// response was written, to mark the pin confirmed.
type Confirmer interface {
	Confirm(pin string) error
}

// serveOpts are Serve's injectable dependencies.
type serveOpts struct {
	deadline time.Duration
}

// defaultServeOpts returns the production dependencies.
//
// Stub: zero values.
func defaultServeOpts() serveOpts { return serveOpts{} }

// Serve handles one pairing exchange on conn against w.
//
// Stub: returns nil.
func Serve(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger) error {
	return serveWith(ctx, conn, w, p, log, defaultServeOpts())
}

// serveWith is Serve with injectable dependencies.
//
// Stub: returns nil.
func serveWith(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger, o serveOpts) error {
	return nil
}
