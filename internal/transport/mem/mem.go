// Package mem provides an in-memory implementation of the transport interfaces
// defined in internal/transport. It is test infrastructure for the dial and
// reconnect machinery: running the full dial-and-serve stack over mem
// eliminates the need for UDP sockets, QUIC crypto, or any OS privileges, making
// the tests fast, deterministic, and free of networking flake.
//
// The core primitive is a Hub — a registry keyed by logical address. A caller
// creates a Transport from the hub for a given address, calls Listen() to register
// a Listener at that address, and Dial() to connect to it. The resulting Conn
// pair satisfies the same semantics as a real QUIC connection: half-close via
// Close(), abrupt teardown via Reset(), peer Context() cancels when the remote
// end closes, and PeerCertificates() returns the peer's configured leaf cert.
package mem

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// ErrClosed is returned by operations on a closed Listener, Conn, or Stream.
var ErrClosed = errors.New("mem: closed")

// ---- Hub ---------------------------------------------------------------------

// Hub is a registry of in-memory listeners keyed by address. Transports created
// from the same Hub can dial each other by registered address.
type Hub struct {
	mu        sync.Mutex
	listeners map[string]*memListener
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{listeners: make(map[string]*memListener)}
}

// Transport returns a transport.Transport bound to addr on this Hub.
// Each call to the returned Transport's Listen() registers addr in the Hub;
// each call to Dial(ctx, target) looks up target in the Hub and delivers a
// connected Conn pair. The provided options configure the local identity cert
// that is surfaced to the peer as PeerCertificates().
func (h *Hub) Transport(addr string, opts ...Option) transport.Transport {
	cfg := &options{}
	for _, o := range opts {
		o(cfg)
	}
	return &memTransport{hub: h, addr: addr, cfg: cfg}
}

// register adds a listener under addr. Returns an error if already registered.
func (h *Hub) register(addr string, ln *memListener) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.listeners[addr]; exists {
		return fmt.Errorf("mem: address %q already registered", addr)
	}
	h.listeners[addr] = ln
	return nil
}

// unregister removes addr from the registry.
func (h *Hub) unregister(addr string) {
	h.mu.Lock()
	delete(h.listeners, addr)
	h.mu.Unlock()
}

// dial connects to the listener at target, delivering the server-side Conn
// via the listener's accept channel and returning the client-side Conn.
// Dialing an unregistered address returns an error wrapping transport.ErrUnreachable.
func (h *Hub) dial(ctx context.Context, dialerCert *x509.Certificate, target string) (transport.Conn, error) {
	h.mu.Lock()
	ln, ok := h.listeners[target]
	h.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: no listener at %q", transport.ErrUnreachable, target)
	}

	// Honour an injected fault on the listener's transport side.
	if ln.failDial != nil {
		return nil, ln.failDial
	}

	client, server := newConnPair(dialerCert, ln.cert)

	select {
	case ln.incoming <- server:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ln.closed:
		return nil, ErrClosed
	}
	return client, nil
}

// ---- Option ------------------------------------------------------------------

// Option configures a mem Transport.
type Option func(*options)

type options struct {
	cert     *x509.Certificate // surfaced to the peer as PeerCertificates()
	failDial error             // if non-nil, every Dial returns this error
}

// WithCert sets the local identity certificate that the peer's
// Conn.PeerCertificates() will return. Mirrors how the QUIC transport exposes
// the peer's TLS leaf certificate after a completed handshake.
func WithCert(leaf *x509.Certificate) Option {
	return func(o *options) { o.cert = leaf }
}

// FailDial makes every Dial on this transport return err immediately, regardless
// of whether a listener is registered. Use transport.ErrAuthFailed to test
// the authentication-failure exit path.
func FailDial(err error) Option {
	return func(o *options) { o.failDial = err }
}

// ---- NewIdentity -------------------------------------------------------------

// NewIdentity generates a fresh Ed25519 identity and returns the carrier
// certificate leaf and its canonical pin string. Use this to mint peer
// certificates for both sides of a mem connection so that
// router.IdentityFromCerts works correctly on the accepted Conn.
func NewIdentity() (*x509.Certificate, string, error) {
	key, err := identity.Generate()
	if err != nil {
		return nil, "", fmt.Errorf("mem: generate key: %w", err)
	}
	tlsCert, err := identity.SelfSignedCarrier(key)
	if err != nil {
		return nil, "", fmt.Errorf("mem: self-signed carrier: %w", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("mem: pin: %w", err)
	}
	return tlsCert.Leaf, pin, nil
}

// ---- memTransport ------------------------------------------------------------

type memTransport struct {
	hub  *Hub
	addr string
	cfg  *options
}

// Dial implements transport.Transport. It looks up target in the Hub and
// returns the client side of a connected Conn pair. If the transport was
// created with FailDial, that error is returned without consulting the Hub.
// Dialing an unregistered address returns transport.ErrUnreachable.
func (t *memTransport) Dial(ctx context.Context, target string) (transport.Conn, error) {
	if t.cfg.failDial != nil {
		return nil, t.cfg.failDial
	}
	return t.hub.dial(ctx, t.cfg.cert, target)
}

// Listen implements transport.Transport. It registers t's address in the Hub
// and returns a Listener. Calling Listen twice on the same address is an error.
func (t *memTransport) Listen() (transport.Listener, error) {
	ln := &memListener{
		addr:     t.addr,
		cert:     t.cfg.cert,
		failDial: t.cfg.failDial,
		incoming: make(chan transport.Conn, 64),
		closed:   make(chan struct{}),
		hub:      t.hub,
	}
	if err := t.hub.register(t.addr, ln); err != nil {
		return nil, err
	}
	return ln, nil
}

// Close implements transport.Transport. It is a no-op on the transport itself;
// the listener unregisters itself from the Hub when it is closed.
func (t *memTransport) Close() error { return nil }

// ---- memListener -------------------------------------------------------------

type memListener struct {
	addr     string
	cert     *x509.Certificate // our own cert, surfaced to dialers as PeerCertificates
	failDial error             // if non-nil, Dial to this listener returns this error
	incoming chan transport.Conn
	closed   chan struct{}
	once     sync.Once
	hub      *Hub
}

// Accept blocks until a dialer connects or ctx is cancelled.
func (l *memListener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case conn := <-l.incoming:
		return conn, nil
	case <-l.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Addr returns the registered address as a net.Addr.
func (l *memListener) Addr() net.Addr { return memAddr(l.addr) }

// Close unregisters the listener from the Hub and closes it so pending
// Accept calls return ErrClosed.
func (l *memListener) Close() error {
	l.once.Do(func() {
		l.hub.unregister(l.addr)
		close(l.closed)
	})
	return nil
}

// memAddr is a minimal net.Addr for a mem listener.
type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

// ---- Conn pair ---------------------------------------------------------------

// connPair is the shared state between the two sides of a mem connection.
// When either side calls CloseWithError, the other's Context is cancelled.
type connPair struct {
	// clientCert is the certificate of the dialer (client); it is returned by
	// the server-side Conn.PeerCertificates().
	clientCert *x509.Certificate
	// serverCert is the certificate of the listener (server); it is returned
	// by the client-side Conn.PeerCertificates().
	serverCert *x509.Certificate

	// Streams opened by either side queue up here for AcceptStream.
	// Index 0 = client→server (client opens, server accepts).
	// Index 1 = server→client (server opens, client accepts).
	streams [2]chan transport.Stream

	// Closing one side fires both sides' context cancels.
	clientCancel context.CancelCauseFunc
	serverCancel context.CancelCauseFunc
	closeOnce    sync.Once
}

// closeConn cancels both contexts with the provided cause. Idempotent.
func (p *connPair) closeConn(cause error) {
	p.closeOnce.Do(func() {
		p.clientCancel(cause)
		p.serverCancel(cause)
	})
}

// newConnPair creates a client/server Conn pair. clientCert is the dialer's
// leaf; serverCert is the listener's leaf (either may be nil).
func newConnPair(clientCert, serverCert *x509.Certificate) (*memConn, *memConn) {
	// Two rendezvous channels — one per direction of stream opening.
	streams := [2]chan transport.Stream{
		make(chan transport.Stream, 64),
		make(chan transport.Stream, 64),
	}

	clientCtx, clientCancel := context.WithCancelCause(context.Background())
	serverCtx, serverCancel := context.WithCancelCause(context.Background())

	pair := &connPair{
		clientCert:   clientCert,
		serverCert:   serverCert,
		streams:      streams,
		clientCancel: clientCancel,
		serverCancel: serverCancel,
	}

	handshakeDone := make(chan struct{})
	close(handshakeDone) // instant handshake

	client := &memConn{
		pair:          pair,
		ctx:           clientCtx,
		peerCert:      serverCert, // client sees server's cert as peer
		openIdx:       0,          // client opens on index 0, accepts on index 1
		acceptIdx:     1,
		handshakeDone: handshakeDone,
	}
	server := &memConn{
		pair:          pair,
		ctx:           serverCtx,
		peerCert:      clientCert, // server sees client's cert as peer
		openIdx:       1,          // server opens on index 1, accepts on index 0
		acceptIdx:     0,
		handshakeDone: handshakeDone,
	}
	return client, server
}

// ---- memConn -----------------------------------------------------------------

type memConn struct {
	pair          *connPair
	ctx           context.Context
	peerCert      *x509.Certificate
	openIdx       int // index into pair.streams for OpenStream
	acceptIdx     int // index into pair.streams for AcceptStream
	handshakeDone chan struct{}
}

// OpenStream opens a new bidirectional stream and delivers the peer-side half
// to the peer's AcceptStream channel. Returns an error if the conn is closed
// or ctx is cancelled.
func (c *memConn) OpenStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-c.ctx.Done():
		return nil, fmt.Errorf("mem: conn closed: %w", context.Cause(c.ctx))
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	local, remote := newStreamPair()

	select {
	case c.pair.streams[c.openIdx] <- remote:
		return local, nil
	case <-c.ctx.Done():
		local.Reset(0)
		remote.Reset(0)
		return nil, fmt.Errorf("mem: conn closed while opening stream: %w", context.Cause(c.ctx))
	case <-ctx.Done():
		local.Reset(0)
		remote.Reset(0)
		return nil, ctx.Err()
	}
}

// AcceptStream blocks until the peer opens a stream or the conn/ctx closes.
func (c *memConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case s := <-c.pair.streams[c.acceptIdx]:
		return s, nil
	case <-c.ctx.Done():
		return nil, fmt.Errorf("mem: conn closed: %w", context.Cause(c.ctx))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Stats returns zeroed ConnStats (no real RTT measurement in-memory).
func (c *memConn) Stats() transport.ConnStats { return transport.ConnStats{} }

// HandshakeComplete returns an already-closed channel — mem connections have
// an instantaneous handshake.
func (c *memConn) HandshakeComplete() <-chan struct{} { return c.handshakeDone }

// Context returns the conn's lifecycle context. It is cancelled when either
// side calls CloseWithError, with the close reason as the cause.
func (c *memConn) Context() context.Context { return c.ctx }

// CloseWithError closes the connection (and its peer) with the given code and
// message. Subsequent operations on either side return an error derived from
// the cause. Idempotent.
func (c *memConn) CloseWithError(code uint64, msg string) error {
	cause := &closeError{code: code, msg: msg}
	c.pair.closeConn(cause)
	return nil
}

// PeerCertificates returns the peer's certificate chain (leaf only). This is
// what router.IdentityFromCerts uses to derive the peer pin.
func (c *memConn) PeerCertificates() []*x509.Certificate {
	if c.peerCert == nil {
		return nil
	}
	return []*x509.Certificate{c.peerCert}
}

// closeError is the context cause set by CloseWithError.
type closeError struct {
	code uint64
	msg  string
}

func (e *closeError) Error() string {
	return fmt.Sprintf("mem: conn closed with code %d: %s", e.code, e.msg)
}

// ---- Stream ------------------------------------------------------------------

// streamResetError is returned by Read/Write on a reset stream.
type streamResetError struct {
	code uint64
}

func (e *streamResetError) Error() string {
	return fmt.Sprintf("mem: stream reset with code %d", e.code)
}

// memStream is a bidirectional in-memory pipe. Each direction is backed by a
// small goroutine-safe byte buffer (rather than a raw io.Pipe) so that gRPC's
// HTTP/2 framing — which writes a frame, then immediately reads a response
// in the same goroutine — does not deadlock on a synchronous pipe.
type memStream struct {
	// read side: data produced by the peer's writes.
	rd *bufPipe
	// write side: data we produce for the peer's reads.
	wr *bufPipe
}

// newStreamPair creates a connected (local, remote) stream pair.
// local.Write → remote.Read; remote.Write → local.Read.
func newStreamPair() (*memStream, *memStream) {
	// Two independent pipes; each direction is independent.
	ab := newBufPipe() // local writes → remote reads
	ba := newBufPipe() // remote writes → local reads
	local := &memStream{rd: ba, wr: ab}
	remote := &memStream{rd: ab, wr: ba}
	return local, remote
}

// Read reads from the receive side of the stream. Returns io.EOF when the
// peer has half-closed its send side via Close(). Returns an error wrapping
// streamResetError when the stream was reset.
func (s *memStream) Read(p []byte) (int, error) { return s.rd.Read(p) }

// Write writes to the send side of the stream. Returns an error if the stream
// has been half-closed (Close) or reset (Reset) on this side.
func (s *memStream) Write(p []byte) (int, error) { return s.wr.Write(p) }

// Close half-closes the send side of this stream (a clean FIN). The peer's
// Read will return io.EOF after draining buffered data. The receive side keeps
// flowing. Implements the half-close requirement: Close ≠ Reset.
func (s *memStream) Close() error { return s.wr.CloseWrite() }

// Reset abruptly terminates both directions of the stream with code. Both
// the peer's Read and Write will return an error carrying code. Never converts
// a half-close into a reset or vice-versa.
func (s *memStream) Reset(code uint64) {
	cause := &streamResetError{code: code}
	s.wr.CloseWithError(cause)
	s.rd.CloseWithError(cause)
}

// ---- bufPipe -----------------------------------------------------------------
//
// bufPipe is a goroutine-safe, bounded in-memory byte pipe used as one
// direction of a mem stream. It uses a condition variable rather than a raw
// io.Pipe so that the writer can return immediately (rather than blocking until
// the reader consumes), which prevents HTTP/2 framing deadlocks where the same
// goroutine writes a frame and then reads the response.

const bufPipeSize = 256 * 1024 // 256 KiB per direction

type bufPipe struct {
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	readErr error // set on CloseWrite (io.EOF) or CloseWithError
	wrErr   error // set on CloseWithError from the read side
	closed  bool
}

func newBufPipe() *bufPipe {
	p := &bufPipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Write appends data to the buffer. Blocks if the buffer is full. Returns an
// error if the write side has been closed.
func (p *bufPipe) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Check if write side is already closed.
	if p.wrErr != nil {
		return 0, p.wrErr
	}
	if p.closed && p.readErr != nil {
		return 0, p.readErr
	}
	total := 0
	for len(data) > 0 {
		// Wait if the buffer is at capacity.
		for len(p.buf) >= bufPipeSize {
			if p.wrErr != nil {
				return total, p.wrErr
			}
			p.cond.Wait()
		}
		if p.wrErr != nil {
			return total, p.wrErr
		}
		space := bufPipeSize - len(p.buf)
		chunk := data
		if len(chunk) > space {
			chunk = chunk[:space]
		}
		p.buf = append(p.buf, chunk...)
		data = data[len(chunk):]
		total += len(chunk)
		p.cond.Broadcast()
	}
	return total, nil
}

// Read drains from the buffer. Blocks until data is available or the write side
// closes. Returns io.EOF when the write side did CloseWrite(); returns the
// stored error when CloseWithError was called from either side.
func (p *bufPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if len(p.buf) > 0 {
			n := copy(b, p.buf)
			p.buf = p.buf[n:]
			p.cond.Broadcast()
			return n, nil
		}
		// Buffer is empty. Check for a close condition.
		if p.readErr != nil {
			return 0, p.readErr
		}
		if p.closed {
			return 0, io.EOF
		}
		p.cond.Wait()
	}
}

// CloseWrite signals a clean EOF on the write side. The reader sees io.EOF
// after draining buffered data.
func (p *bufPipe) CloseWrite() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
	}
	p.mu.Unlock()
	p.cond.Broadcast()
	return nil
}

// CloseWithError closes both directions with the given error. Pending reads
// and writes return err.
func (p *bufPipe) CloseWithError(err error) {
	p.mu.Lock()
	if p.readErr == nil {
		p.readErr = err
	}
	if p.wrErr == nil {
		p.wrErr = err
	}
	p.closed = true
	p.mu.Unlock()
	p.cond.Broadcast()
}
