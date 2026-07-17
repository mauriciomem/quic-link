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

// ErrAuthFailed is a typed sentinel wrapped by classifyDialError when the peer
// rejects the pinning handshake. main() maps it to the authentication-failure
// exit code. A wrong pin never self-heals, so the reconnect loop treats it as
// non-retriable.
var ErrAuthFailed = errors.New("transport: peer authentication failed (pin rejected)")

// TLS alerts map to QUIC transport error codes 0x100 + alert (RFC 9001).
const (
	// tlsAlertBase is the offset QUIC adds to a TLS alert number.
	tlsAlertBase = 0x100
	// tlsAlertMax is the top of the TLS-alert code range.
	tlsAlertMax = 0x1ff
	// alertNoAppProtocol is 0x100 + no_application_protocol (alert 120): the
	// peers negotiated different ALPN identifiers, i.e. mismatched versions.
	alertNoAppProtocol = 0x178
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
//   - TransportError alertNoAppProtocol → ALPN/version mismatch (rebuild both)
//   - TransportError in the TLS-alert range → pin rejected (wraps ErrAuthFailed)
//   - ConnectionRefused → server actively refused (may be a pin mismatch)
func classifyDialError(err error) error {
	var handshakeTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &handshakeTimeout) {
		return fmt.Errorf(
			"handshake timeout (UDP blocked or server unreachable; verify the"+
				" server port is reachable from this host): %w", err)
	}
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		// A differing ALPN identifier fails the handshake with
		// no_application_protocol — almost always mismatched binary versions.
		// Name it distinctly so the operator rebuilds both binaries instead of
		// chasing pins. This is a real, distinct failure — not an auth error.
		if transportErr.ErrorCode == alertNoAppProtocol {
			return fmt.Errorf(
				"protocol/version mismatch (TLS alert no_application_protocol"+
					" 0x178; client and server ALPN differ — rebuild both"+
					" binaries from the same version): %w", err)
		}
		// Any other TLS alert (RFC 9001) under raw-public-key pinning is the
		// peer rejecting the pin (e.g. bad_certificate from our
		// VerifyPeerCertificate callback). Wrap ErrAuthFailed so main() exits
		// with the auth-failure code and the reconnect loop stops retrying.
		if transportErr.ErrorCode >= tlsAlertBase && transportErr.ErrorCode <= tlsAlertMax {
			return fmt.Errorf(
				"%w (TLS error 0x%x; the peer pin was not accepted — verify"+
					" --pin (client) and --authorized-client (agent) on both"+
					" ends): %w",
				ErrAuthFailed, uint64(transportErr.ErrorCode), err)
		}
		if transportErr.ErrorCode == quic.ConnectionRefused {
			return fmt.Errorf(
				"connection refused (server rejected the connection;"+
					" verify the pins on both ends): %w", err)
		}
	}
	return err
}

// AuthError reports whether err (typically a connection-close cause or a
// post-handshake read error) indicates the peer rejected authentication — a
// TLS-alert-range QUIC transport error other than an ALPN mismatch. It returns
// the error wrapped in ErrAuthFailed, or nil if err is not an auth rejection.
// This lets callers detect a pin rejection that arrives AFTER the local
// handshake completes (the agent-rejects-client direction), where the failure
// surfaces on the connection rather than at Dial.
func AuthError(err error) error {
	var te *quic.TransportError
	if errors.As(err, &te) &&
		te.ErrorCode >= tlsAlertBase && te.ErrorCode <= tlsAlertMax &&
		te.ErrorCode != alertNoAppProtocol {
		return fmt.Errorf("%w (peer rejected the pin: TLS error 0x%x)", ErrAuthFailed, uint64(te.ErrorCode))
	}
	return nil
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

// SetDeadline/SetReadDeadline/SetWriteDeadline delegate to the underlying QUIC
// stream, which supports them natively. They are not part of the transport.Stream
// interface (the splice engine never needs them); the control-plane net.Conn
// adapter type-asserts for them so gRPC gets real deadlines.
func (q *quicStream) SetDeadline(t time.Time) error      { return q.s.SetDeadline(t) }
func (q *quicStream) SetReadDeadline(t time.Time) error  { return q.s.SetReadDeadline(t) }
func (q *quicStream) SetWriteDeadline(t time.Time) error { return q.s.SetWriteDeadline(t) }

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
