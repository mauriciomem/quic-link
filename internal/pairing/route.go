package pairing

import (
	"context"
	"net"
	"net/netip"
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

// maxPairConnsPerSource bounds the pairing conversations one source runs at
// once, keyed like the window's budget (sourceKey: IPv4 /32, IPv6 /64).
const maxPairConnsPerSource = 2

// routeOpts are a routed listener's test hooks.
type routeOpts struct {
	// released, if set, runs after a handler's counts were released (test hook).
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

	mu        sync.Mutex // guards closed, running, perSource and the Add side of wg
	closed    bool
	running   int                  // handlers running
	perSource map[netip.Prefix]int // handlers running per source key; never holds a zero
	wg        sync.WaitGroup
}

// NewRoutedListener wraps ln. Accept returns only connections that negotiated
// transport.ALPN. A connection that negotiated transport.ALPNPair is passed to
// handle in its own goroutine; every other connection - empty or unknown ALPN,
// or a Conn that does not implement transport.ALPNProvider - is closed with
// CodePairRejected and never returned. ln's Conns must be the transport's own
// (not wrapped), or the optional interfaces are lost and everything is refused.
//
// At most maxPairConns handlers run at once, and at most maxPairConnsPerSource
// from one source (the IPv4 /32 or IPv6 /64 the window budgets on); a pairing
// connection over either cap is closed with CodePairBusy, never queued, and one
// whose UDP source cannot be read is closed with CodePairRejected. Handlers run
// under a context that Close cancels, and Close returns only after every
// handler has. A nil handle refuses pairing connections like an unknown
// protocol. Many distinct sources can still fill the global cap; that is
// accepted, like the per-window source table bound.
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

		perSource: make(map[netip.Prefix]int),
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
	from, err := udpSource(c)
	key, ok := sourceKey(from.Addr())
	if err != nil || !ok {
		// Fail closed: Serve would refuse it anyway; do not spend a slot.
		_ = c.CloseWithError(CodePairRejected, "")
		return
	}
	l.mu.Lock()
	var code uint64
	switch {
	case l.closed:
		code = CodePairRejected
	case l.running >= maxPairConns || l.perSource[key] >= maxPairConnsPerSource:
		code = CodePairBusy
	default:
		l.running++
		l.perSource[key]++
		l.wg.Add(1)
	}
	l.mu.Unlock()
	if code != 0 {
		_ = c.CloseWithError(code, "")
		return
	}
	go func() {
		defer l.wg.Done()
		defer l.release(key)
		l.handle(l.ctx, c)
	}()
}

// release returns a finished handler's counts, then runs the test hook. The
// hook runs after the unlock, so once it fires the freed slot is visible to
// the next dispatch.
func (l *routedListener) release(key netip.Prefix) {
	l.mu.Lock()
	l.running--
	if n := l.perSource[key] - 1; n == 0 {
		delete(l.perSource, key)
	} else {
		l.perSource[key] = n
	}
	l.mu.Unlock()
	if l.opts.released != nil {
		l.opts.released()
	}
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
