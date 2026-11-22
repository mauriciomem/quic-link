/**
 * @spec-handoff
 * @interface NewRoutedListener(ln transport.Listener, handle func(context.Context, transport.Conn)) transport.Listener; const CodePairRejected = 0x50, CodePairBusy = 0x51
 * @behavior
 *   - Accept returns only connections whose NEGOTIATED ALPN (transport.ALPNProvider) is transport.ALPN, in arrival order; it loops internally over the others
 *   - transport.ALPNPair -> handle(ctx, conn) in its own goroutine (Accept never waits for a handler); the listener does not close it
 *   - "" / any other ALPN (exact match, case-sensitive) / a Conn without ALPNProvider -> CloseWithError(CodePairRejected), never returned, never handled
 *   - at most 16 handlers run at once; a pair1 connection arriving at the cap is closed with CodePairBusy at once (never queued, never handled); a slot frees when a handler returns
 *   - handler ctx: derived at construction (not from Accept's ctx), cancelled by Close; Close cancels, closes ln, and returns only after every handler returned
 *   - Accept returns ln.Accept's error unchanged; Addr is ln.Addr
 * @edge-cases
 *   - quic-link/1 connections are still returned while the pairing cap is full
 * @see ./route.go ../transport/iface.go
 */

package pairing_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/pairing"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// routeWait bounds every wait in the routed-listener tests.
const routeWait = 2 * time.Second

// fakeConn is a transport.Conn with no optional interfaces. It records the
// first CloseWithError code.
type fakeConn struct {
	name   string
	ctx    context.Context
	cancel context.CancelFunc
	closed chan uint64 // receives the first close code
	once   sync.Once
}

func newFakeConn(name string) *fakeConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConn{name: name, ctx: ctx, cancel: cancel, closed: make(chan uint64, 1)}
}

func (c *fakeConn) OpenStream(context.Context) (transport.Stream, error) {
	return nil, errors.New("fakeConn: no streams")
}

func (c *fakeConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, errors.New("fakeConn: closed")
	}
}
func (c *fakeConn) Stats() transport.ConnStats { return transport.ConnStats{} }
func (c *fakeConn) HandshakeComplete() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
func (c *fakeConn) Context() context.Context { return c.ctx }
func (c *fakeConn) CloseWithError(code uint64, _ string) error {
	c.once.Do(func() {
		c.closed <- code
		c.cancel()
	})
	return nil
}
func (c *fakeConn) PeerCertificates() []*x509.Certificate { return nil }

// closeCode returns the code the conn was closed with, or false if it was not
// closed within d.
func (c *fakeConn) closeCode(d time.Duration) (uint64, bool) {
	select {
	case code := <-c.closed:
		c.closed <- code
		return code, true
	default:
	}
	if d <= 0 {
		return 0, false
	}
	select {
	case code := <-c.closed:
		c.closed <- code // keep it for later reads
		return code, true
	case <-time.After(d):
		return 0, false
	}
}

// alpnConn is a fakeConn that reports a negotiated protocol.
type alpnConn struct {
	*fakeConn
	proto string
}

func (c *alpnConn) NegotiatedProtocol() string { return c.proto }

func newALPNConn(name, proto string) *alpnConn {
	return &alpnConn{fakeConn: newFakeConn(name), proto: proto}
}

// connName names a conn for messages.
func connName(c transport.Conn) string {
	switch v := c.(type) {
	case *alpnConn:
		return v.name
	case *fakeConn:
		return v.name
	default:
		return "?"
	}
}

func fakeOf(c transport.Conn) *fakeConn {
	switch v := c.(type) {
	case *alpnConn:
		return v.fakeConn
	case *fakeConn:
		return v
	}
	return nil
}

var errFakeListenerClosed = errors.New("fakeListener: closed")

// fakeListener hands out the conns pushed into it.
type fakeListener struct {
	in        chan transport.Conn
	errs      chan error // an error to return from the next Accept
	done      chan struct{}
	closeOnce sync.Once
	closes    atomic.Int32
}

func newFakeListener() *fakeListener {
	return &fakeListener{in: make(chan transport.Conn, 64), errs: make(chan error, 4), done: make(chan struct{})}
}

func (l *fakeListener) push(cs ...transport.Conn) {
	for _, c := range cs {
		l.in <- c
	}
}

func (l *fakeListener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case c := <-l.in:
		return c, nil
	case err := <-l.errs:
		return nil, err
	case <-l.done:
		return nil, errFakeListenerClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var fakeAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4242}

func (l *fakeListener) Addr() net.Addr { return fakeAddr }
func (l *fakeListener) Close() error {
	l.closes.Add(1)
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

// handlerSpy records every handled conn. With gate set, each call blocks
// until gate is closed or the handler ctx ends.
type handlerSpy struct {
	mu      sync.Mutex
	conns   []transport.Conn
	ctxs    []context.Context
	entered chan transport.Conn
	gate    chan struct{}
	exited  atomic.Int32
	running atomic.Int32
	maxRun  atomic.Int32
}

func newHandlerSpy(gated bool) *handlerSpy {
	h := &handlerSpy{entered: make(chan transport.Conn, 64)}
	if gated {
		h.gate = make(chan struct{})
	}
	return h
}

func (h *handlerSpy) handle(ctx context.Context, c transport.Conn) {
	n := h.running.Add(1)
	for {
		m := h.maxRun.Load()
		if n <= m || h.maxRun.CompareAndSwap(m, n) {
			break
		}
	}
	h.mu.Lock()
	h.conns = append(h.conns, c)
	h.ctxs = append(h.ctxs, ctx)
	h.mu.Unlock()
	h.entered <- c
	if h.gate != nil {
		select {
		case <-h.gate:
		case <-ctx.Done():
		}
	}
	h.running.Add(-1)
	h.exited.Add(1)
}

func (h *handlerSpy) handled() []transport.Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]transport.Conn(nil), h.conns...)
}

// waitEntered waits for n more handler calls.
func (h *handlerSpy) waitEntered(t *testing.T, n int) []transport.Conn {
	t.Helper()
	var got []transport.Conn
	deadline := time.After(routeWait)
	for len(got) < n {
		select {
		case c := <-h.entered:
			got = append(got, c)
		case <-deadline:
			t.Fatalf("handler entered %d of %d times within %v: pair1 connections are not dispatched to the handler", len(got), n, routeWait)
		}
	}
	return got
}

// acceptLoop calls Accept until it fails and reports every returned conn.
type acceptLoop struct {
	got  chan transport.Conn
	err  chan error
	done chan struct{}
}

func startAcceptLoop(ctx context.Context, ln transport.Listener) *acceptLoop {
	a := &acceptLoop{got: make(chan transport.Conn, 64), err: make(chan error, 1), done: make(chan struct{})}
	go func() {
		defer close(a.done)
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				a.err <- err
				return
			}
			a.got <- c
		}
	}()
	return a
}

// next waits for the next conn Accept returns.
func (a *acceptLoop) next(t *testing.T) transport.Conn {
	t.Helper()
	select {
	case c := <-a.got:
		return c
	case err := <-a.err:
		t.Fatalf("Accept failed before returning a connection: %v", err)
	case <-time.After(routeWait):
		t.Fatalf("Accept returned nothing within %v", routeWait)
	}
	return nil
}

// none requires Accept to return nothing for d.
func (a *acceptLoop) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case c := <-a.got:
		t.Errorf("Accept returned %s (%T); want only quic-link/1 connections returned", connName(c), c)
	case <-time.After(d):
	}
}

// routeLeakCheck snapshots the goroutines running now and checks at cleanup
// that no other goroutine is left. It runs after every later cleanup.
func routeLeakCheck(t *testing.T) {
	t.Helper()
	opt := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, opt) })
}

func TestRoutedListener_RoutesByNegotiatedProtocol(t *testing.T) {
	if pairing.CodePairRejected != 0x50 || pairing.CodePairBusy != 0x51 {
		t.Fatalf("CodePairRejected = %#x, CodePairBusy = %#x; want 0x50, 0x51", pairing.CodePairRejected, pairing.CodePairBusy)
	}
	routeLeakCheck(t)
	fl := newFakeListener()
	h := newHandlerSpy(true)
	rl := pairing.NewRoutedListener(fl, h.handle)
	ctx, cancel := context.WithCancel(context.Background())
	var loop *acceptLoop
	t.Cleanup(func() {
		close(h.gate)
		cancel()
		rl.Close()
		if loop != nil {
			<-loop.done
		}
	})

	if got := rl.Addr(); got != fakeAddr {
		t.Errorf("Addr() = %v, want the wrapped listener's %v", got, fakeAddr)
	}

	rejected := []transport.Conn{
		newALPNConn("empty ALPN", ""),
		newALPNConn("unknown ALPN", "h3"),
		newALPNConn("older protocol", "quic-link/0"),
		newALPNConn("case variant of quic-link/1", "QUIC-LINK/1"),
		newALPNConn("case variant of pair1", "QUIC-LINK/PAIR1"),
		newALPNConn("pair1 prefix", "quic-link/pair"),
		newALPNConn("quic-link/1 with suffix", transport.ALPN+" "),
		newFakeConn("no ALPNProvider"),
	}
	pair := newALPNConn("pair1", transport.ALPNPair)
	steady1 := newALPNConn("quic-link/1 first", transport.ALPN)
	steady2 := newALPNConn("quic-link/1 second", transport.ALPN)

	// Refused connections and a pairing one arrive before any steady one, so
	// Accept has to skip them to return steady1.
	fl.push(rejected...)
	fl.push(pair, steady1, steady2)
	loop = startAcceptLoop(ctx, rl)

	if got := loop.next(t); got != transport.Conn(steady1) {
		t.Errorf("first Accept returned %s (%T), want %q", connName(got), got, steady1.name)
	}
	if got := loop.next(t); got != transport.Conn(steady2) {
		t.Errorf("second Accept returned %s (%T), want %q", connName(got), got, steady2.name)
	}
	loop.none(t, 100*time.Millisecond)

	end := time.Now().Add(routeWait) // one budget for all of them
	for _, c := range rejected {
		code, ok := fakeOf(c).closeCode(max(time.Until(end), time.Millisecond))
		if !ok {
			t.Errorf("%s: not closed; want CloseWithError(CodePairRejected)", connName(c))
			continue
		}
		if code != pairing.CodePairRejected {
			t.Errorf("%s: closed with %#x, want CodePairRejected %#x", connName(c), code, pairing.CodePairRejected)
		}
	}

	hs := h.waitEntered(t, 1)
	if hs[0] != transport.Conn(pair) {
		t.Errorf("handler got %s, want the pair1 connection", connName(hs[0]))
	}
	for _, c := range h.handled() {
		if c != transport.Conn(pair) {
			t.Errorf("handler got %s; only pair1 connections may reach it", connName(c))
		}
	}
	if _, closed := pair.closeCode(50 * time.Millisecond); closed {
		t.Error("the listener closed the pair1 connection it handed to the handler")
	}
	for _, c := range []*alpnConn{steady1, steady2} {
		if code, closed := c.closeCode(0); closed {
			t.Errorf("%s: the listener closed a returned quic-link/1 connection (code %#x)", c.name, code)
		}
	}

	t.Run("Accept returns the wrapped listener's error unchanged", func(t *testing.T) {
		boom := errors.New("accept: boom")
		fl.errs <- boom
		select {
		case err := <-loop.err:
			if err != boom {
				t.Errorf("Accept error = %v (%T), want the wrapped listener's error itself", err, err)
			}
		case c := <-loop.got:
			t.Errorf("Accept returned %s instead of the error", connName(c))
		case <-time.After(routeWait):
			t.Error("Accept did not return the wrapped listener's error")
		}
	})
}

func TestRoutedListener_CloseWaitsForHandlers(t *testing.T) {
	routeLeakCheck(t)
	fl := newFakeListener()

	var (
		exited   atomic.Bool
		handlerC = make(chan context.Context, 1)
		running  = make(chan struct{})
	)
	handle := func(ctx context.Context, _ transport.Conn) {
		handlerC <- ctx
		close(running)
		<-ctx.Done()
		// Work done after cancellation must still finish before Close returns.
		time.Sleep(100 * time.Millisecond)
		exited.Store(true)
	}
	rl := pairing.NewRoutedListener(fl, handle)

	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	loop := startAcceptLoop(acceptCtx, rl)
	pair := newALPNConn("pair1", transport.ALPNPair)
	fl.push(pair)

	var hctx context.Context
	select {
	case hctx = <-handlerC:
	case c := <-loop.got:
		rl.Close()
		cancelAccept()
		<-loop.done
		t.Fatalf("Accept returned %s instead of handing it to the handler", connName(c))
	case <-time.After(routeWait):
		rl.Close()
		cancelAccept()
		<-loop.done
		t.Fatal("the handler never ran for a pair1 connection")
	}
	<-running

	// Cancelling Accept's ctx must not cancel the handler: its ctx belongs to
	// the listener.
	cancelAccept()
	select {
	case err := <-loop.err:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Accept after its ctx was cancelled = %v, want context.Canceled", err)
		}
	case <-time.After(routeWait):
		t.Error("Accept did not return after its ctx was cancelled")
	}
	<-loop.done
	if hctx.Err() != nil {
		t.Errorf("handler ctx ended with Accept's ctx (%v); it must end only with Close", hctx.Err())
	}

	closed := make(chan error, 1)
	go func() { closed <- rl.Close() }()
	select {
	case <-closed:
	case <-time.After(routeWait):
		t.Fatal("Close did not return: it must cancel the handler ctx and wait")
	}
	if !exited.Load() {
		t.Error("Close returned before the handler did")
	}
	if hctx.Err() == nil {
		t.Error("handler ctx not cancelled by Close")
	}
	if n := fl.closes.Load(); n < 1 {
		t.Error("Close did not close the wrapped listener")
	}

	t.Run("Accept after Close returns the wrapped listener's error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), routeWait)
		defer cancel()
		c, err := rl.Accept(ctx)
		if c != nil || !errors.Is(err, errFakeListenerClosed) {
			t.Errorf("Accept after Close = (%v, %v), want (nil, the wrapped listener's close error)", c, err)
		}
	})
}

func TestRoutedListener_PairConnCap(t *testing.T) {
	const wantCap = 16
	routeLeakCheck(t)
	fl := newFakeListener()
	h := newHandlerSpy(true)
	rl := pairing.NewRoutedListener(fl, h.handle)
	ctx, cancel := context.WithCancel(context.Background())
	loop := startAcceptLoop(ctx, rl)
	var gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(h.gate) }) }
	t.Cleanup(func() {
		release()
		cancel()
		rl.Close()
		<-loop.done
	})

	// Boundary, below: the 16th concurrent exchange is admitted.
	held := make([]*alpnConn, wantCap)
	for i := range held {
		held[i] = newALPNConn("pair1 held", transport.ALPNPair)
		fl.push(held[i])
	}
	h.waitEntered(t, wantCap)
	for i, c := range held {
		if code, closed := c.closeCode(0); closed {
			t.Errorf("held pair1 #%d closed with %#x below the cap", i+1, code)
		}
	}

	// Boundary, above: the 17th is refused busy at once, never queued.
	over := newALPNConn("pair1 over the cap", transport.ALPNPair)
	fl.push(over)
	code, closed := over.closeCode(routeWait)
	switch {
	case !closed:
		t.Errorf("17th concurrent pair1 connection not closed within %v; want CodePairBusy, never queued", routeWait)
	case code != pairing.CodePairBusy:
		t.Errorf("17th concurrent pair1 connection closed with %#x, want CodePairBusy %#x", code, pairing.CodePairBusy)
	}
	if n := len(h.handled()); n != wantCap {
		t.Errorf("handler ran %d times, want %d (the refused one must never be handled)", n, wantCap)
	}
	if m := h.maxRun.Load(); m > wantCap {
		t.Errorf("%d handlers ran at once, want at most %d", m, wantCap)
	}

	// The cap is on pairing only: a steady connection still comes out.
	steady := newALPNConn("quic-link/1 at the cap", transport.ALPN)
	fl.push(steady)
	if got := loop.next(t); got != transport.Conn(steady) {
		t.Errorf("Accept at the pairing cap returned %s, want the quic-link/1 connection", connName(got))
	}

	// A slot frees when a handler returns: release all, then a new pair1
	// connection is handled again.
	release()
	deadline := time.After(routeWait)
	for h.exited.Load() < wantCap {
		select {
		case <-deadline:
			t.Fatalf("only %d of %d handlers returned after release", h.exited.Load(), wantCap)
		case <-time.After(5 * time.Millisecond):
		}
	}
	again := newALPNConn("pair1 after release", transport.ALPNPair)
	fl.push(again)
	if got := h.waitEntered(t, 1); got[0] != transport.Conn(again) {
		t.Errorf("handler got %s after slots freed, want the new pair1 connection", connName(got[0]))
	}
	if code, closed := again.closeCode(50 * time.Millisecond); closed {
		t.Errorf("pair1 connection after slots freed closed with %#x; the cap counts running handlers, not totals", code)
	}
}
