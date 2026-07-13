package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

// defaultQUICConfig returns the recommended quic.Config for quic-link.
// DPLPMTUD (RFC 8899) remains enabled (DisablePathMTUDiscovery is false).
func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		// Send a PING every 15 s so idle connections are not dropped by NAT.
		KeepAlivePeriod: 15 * time.Second,
		// Drop the connection if nothing arrives for 60 s after handshake.
		MaxIdleTimeout: 60 * time.Second,
		// Abort a handshake that takes longer than 5 s so blocked UDP is
		// detected quickly rather than hanging for a long time.
		HandshakeIdleTimeout: 5 * time.Second,
	}
}

// QUICTransport implements Transport over a single UDP socket via quic-go.
// A single socket demultiplexes both the server listener and any dialled
// connections (quic.Transport handles this via Connection IDs per RFC 9000).
type QUICTransport struct {
	tlsConf  *tls.Config
	quicConf *quic.Config
	inner    *quic.Transport
}

// NewQUICTransport creates a QUICTransport from a pre-bound *net.UDPConn.
// tlsConf must not be nil; set NextProtos to []string{ALPN} on both sides.
// quicConf may be nil to use the defaults returned by defaultQUICConfig.
func NewQUICTransport(conn *net.UDPConn, tlsConf *tls.Config, quicConf *quic.Config) (*QUICTransport, error) {
	if tlsConf == nil {
		return nil, fmt.Errorf("tlsConf must not be nil")
	}
	if quicConf == nil {
		quicConf = defaultQUICConfig()
	}
	return &QUICTransport{
		tlsConf:  tlsConf,
		quicConf: quicConf,
		inner:    &quic.Transport{Conn: conn},
	}, nil
}

// Listen implements Transport.  The listen address is determined by the
// *net.UDPConn that was passed to NewQUICTransport.
func (t *QUICTransport) Listen() (Listener, error) {
	l, err := t.inner.Listen(t.tlsConf, t.quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	return &quicListener{l: l}, nil
}

// Dial implements Transport.  addr must be a "host:port" string.
func (t *QUICTransport) Dial(ctx context.Context, addr string) (Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", addr, err)
	}
	conn, err := t.inner.Dial(ctx, udpAddr, t.tlsConf, t.quicConf)
	if err != nil {
		return nil, classifyDialError(err)
	}
	return &quicConn{c: conn}, nil
}

// Close implements Transport.
func (t *QUICTransport) Close() error {
	return t.inner.Close()
}

// classifyDialError wraps connection-setup errors with actionable messages:
//   - HandshakeTimeoutError  → UDP likely blocked by firewall
//   - TransportError 0x178   → ALPN/version mismatch (rebuild both binaries)
//   - TransportError 0x100–0x1ff → TLS certificate rejected (RFC 9001)
//   - ConnectionRefused → server actively refused (may be cert rejection)
func classifyDialError(err error) error {
	var handshakeTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &handshakeTimeout) {
		return fmt.Errorf(
			"handshake timeout (UDP blocked or server unreachable; verify the"+
				" server port is reachable from this host): %w", err)
	}
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		// TLS alerts map to QUIC codes 0x100+alert (RFC 9001).
		// no_application_protocol (alert 120) → 0x178 means the peers' ALPN
		// identifiers differ — almost always mismatched binary versions
		// (e.g. one still speaks quic-link/0). Name it distinctly so the
		// operator rebuilds both binaries instead of chasing certificates.
		if transportErr.ErrorCode == 0x178 {
			return fmt.Errorf(
				"protocol/version mismatch (TLS alert no_application_protocol"+
					" 0x178; client and server ALPN differ — rebuild both"+
					" binaries from the same version): %w", err)
		}
		// Other TLS alert errors land in [0x100, 0x1ff] per RFC 9001.
		if transportErr.ErrorCode >= 0x100 && transportErr.ErrorCode <= 0x1ff {
			return fmt.Errorf(
				"auth failed (TLS error 0x%x; ensure the client cert is signed"+
					" by a CA in the server's --client-ca): %w",
				uint64(transportErr.ErrorCode), err)
		}
		if transportErr.ErrorCode == quic.ConnectionRefused {
			return fmt.Errorf(
				"connection refused (server rejected the connection;"+
					" verify --client-ca on the server): %w", err)
		}
	}
	return err
}

// ---- quicListener wraps *quic.Listener ----------------------------------------

type quicListener struct {
	l *quic.Listener
}

func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
	c, err := l.l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConn{c: c}, nil
}

func (l *quicListener) Addr() net.Addr { return l.l.Addr() }
func (l *quicListener) Close() error   { return l.l.Close() }

// ---- quicConn wraps *quic.Conn ------------------------------------------------

type quicConn struct {
	c *quic.Conn
}

// ---- quicStream wraps *quic.Stream ------------------------------------------

// quicStream adapts *quic.Stream to transport.Stream. Read/Write/Close pass
// through (Close sends a FIN on the send direction only); Reset issues a QUIC
// stream reset on both directions.
type quicStream struct {
	s *quic.Stream
}

func (q *quicStream) Read(p []byte) (int, error)  { return q.s.Read(p) }
func (q *quicStream) Write(p []byte) (int, error) { return q.s.Write(p) }
func (q *quicStream) Close() error                { return q.s.Close() }

func (q *quicStream) Reset(code uint64) {
	ec := quic.StreamErrorCode(code)
	q.s.CancelWrite(ec)
	q.s.CancelRead(ec)
}

// OpenStream opens a new bidirectional QUIC stream (blocks until stream limit
// allows it or ctx is cancelled); the stream is wrapped by quicStream.
func (c *quicConn) OpenStream(ctx context.Context) (Stream, error) {
	s, err := c.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{s: s}, nil
}

// AcceptStream waits for the peer to open a new bidirectional stream;
// the stream is wrapped by quicStream.
func (c *quicConn) AcceptStream(ctx context.Context) (Stream, error) {
	s, err := c.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{s: s}, nil
}

// Stats returns RTT statistics from the QUIC connection.
func (c *quicConn) Stats() ConnStats {
	cs := c.c.ConnectionStats()
	return ConnStats{
		MinRTT:      cs.MinRTT,
		SmoothedRTT: cs.SmoothedRTT,
		LatestRTT:   cs.LatestRTT,
	}
}

func (c *quicConn) HandshakeComplete() <-chan struct{} {
	return c.c.HandshakeComplete()
}

func (c *quicConn) Context() context.Context {
	return c.c.Context()
}

func (c *quicConn) CloseWithError(code uint64, msg string) error {
	return c.c.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// PeerCertificates returns the verified peer certificate chain from the QUIC
// connection's completed TLS handshake (leaf first).
func (c *quicConn) PeerCertificates() []*x509.Certificate {
	return c.c.ConnectionState().TLS.PeerCertificates
}
