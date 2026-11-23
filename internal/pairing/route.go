package pairing

import (
	"context"
	"net"
	"sync"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Application close codes used on pairing connections only. They live in the
// connection close-code namespace; that CodePairRejected equals FrameVersion,
// the pairing frame version byte, is a coincidence between two namespaces.
const (
	CodePairRejected = 0x50 // not a protocol this listener serves
	CodePairBusy     = 0x51 // too many pairing conversations in progress
)

// maxPairConns bounds the pairing conversations handled at once. A pairing
// exchange is a single short request, so a legitimate joiner never needs a
// queue; refusing at the cap keeps a flood from holding goroutines.
const maxPairConns = 16

// routeOpts are a routed listener's test hooks.
type routeOpts struct {
	// released, if set, runs after a handler's slot was released (test hook).
	released func()
}

// routedListener is the transport.Listener NewRoutedListener returns.
type routedListener struct {
	ln     transport.Listener
	handle func(context.Context, transport.Conn)
	opts   routeOpts

	// ctx is the handlers' context: it belongs to the listener, not to any
	// Accept call, and ends only with Close.
	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{} // one token per running handler

	mu     sync.Mutex // guards closed and the Add side of wg
	closed bool
	wg     sync.WaitGroup
}

// NewRoutedListener wraps ln. Accept returns only connections that negotiated
// transport.ALPN. A connection that negotiated transport.ALPNPair is passed to
// handle in its own goroutine; every other connection - empty or unknown ALPN,
// or a Conn that does not implement transport.ALPNProvider - is closed with
// CodePairRejected and never returned. ln's Conns must be the transport's own
// (not wrapped), or the optional interfaces are lost and everything is refused.
//
// At most maxPairConns handlers run at once; a pairing connection arriving at
// the cap is closed with CodePairBusy, never queued. Handlers run under a
// context that Close cancels, and Close returns only after every handler has.
// A nil handle refuses pairing connections like an unknown protocol.
func NewRoutedListener(ln transport.Listener, handle func(context.Context, transport.Conn)) transport.Listener {
	return newRoutedListener(ln, handle, routeOpts{})
}

// newRoutedListener is NewRoutedListener with test hooks.
func newRoutedListener(ln transport.Listener, handle func(context.Context, transport.Conn), o routeOpts) *routedListener {
	ctx, cancel := context.WithCancel(context.Background())
	return &routedListener{
		ln:     ln,
		handle: handle,
		opts:   o,
		ctx:    ctx,
		cancel: cancel,
		slots:  make(chan struct{}, maxPairConns),
	}
}

// Accept returns the next quic-link/1 connection. It dispatches or refuses
// every other connection in between, and returns ln.Accept's error unchanged.
func (l *routedListener) Accept(ctx context.Context) (transport.Conn, error) {
	for {
		c, err := l.ln.Accept(ctx)
		if err != nil {
			return nil, err
		}
		switch negotiatedProtocol(c) {
		case transport.ALPN:
			return c, nil
		case transport.ALPNPair:
			l.dispatch(c)
		default:
			_ = c.CloseWithError(CodePairRejected, "")
		}
	}
}

// negotiatedProtocol is c's negotiated ALPN, or "" when c cannot tell.
func negotiatedProtocol(c transport.Conn) string {
	if a, ok := c.(transport.ALPNProvider); ok {
		return a.NegotiatedProtocol()
	}
	return ""
}

// dispatch runs the handler for a pairing connection in its own goroutine,
// or refuses the connection when it cannot.
func (l *routedListener) dispatch(c transport.Conn) {
	if l.handle == nil {
		_ = c.CloseWithError(CodePairRejected, "")
		return
	}
	select {
	case l.slots <- struct{}{}:
	default:
		_ = c.CloseWithError(CodePairBusy, "")
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		<-l.slots
		_ = c.CloseWithError(CodePairRejected, "")
		return
	}
	l.wg.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.wg.Done()
		defer func() {
			<-l.slots
			if l.opts.released != nil {
				l.opts.released()
			}
		}()
		l.handle(l.ctx, c)
	}()
}

func (l *routedListener) Addr() net.Addr { return l.ln.Addr() }

// Close cancels the handlers' context, closes ln and waits for every handler
// to return. It returns ln.Close's error.
func (l *routedListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.cancel()
	err := l.ln.Close()
	l.wg.Wait()
	return err
}
