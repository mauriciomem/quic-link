package pairing

import (
	"context"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Application close codes used on pairing connections only. They live in the
// connection close-code namespace; that CodePairRejected equals FrameVersion,
// the pairing frame version byte, is a coincidence between two namespaces.
const (
	CodePairRejected = 0x50 // not a protocol this listener serves
	CodePairBusy     = 0x51 // too many pairing conversations in progress
)

// NewRoutedListener wraps ln. Accept returns only connections that negotiated
// transport.ALPN. A connection that negotiated transport.ALPNPair is passed to
// handle in its own goroutine; every other connection is closed with
// CodePairRejected and never returned.
//
// Stub: returns ln unchanged.
func NewRoutedListener(ln transport.Listener, handle func(context.Context, transport.Conn)) transport.Listener {
	return ln
}
