// Package transport defines the Transport abstraction used by quic-link.
// The QUIC implementation is the only concrete implementation shipped today;
// the interfaces below are kept transport-agnostic in shape (Stream/Conn
// wrap io/net primitives, not QUIC-specific types) so a second transport
// could implement them without a redesign, though none is planned.
package transport

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"time"
)

// ALPN is the TLS Application-Layer Protocol Negotiation identifier for
// protocol v1 (framed streams). Both client and agent MUST include
// this in tls.Config.NextProtos. A version mismatch fails the QUIC handshake
// at ALPN (TLS alert no_application_protocol, QUIC 0x178) rather than
// misparsing — see transport.classifyDialError. "quic-link/0" was the earlier
// frameless tunnel; it is intentionally incompatible with v1.
const ALPN = "quic-link/1"

// ConnStats holds RTT measurements derived from the QUIC loss-detection
// machinery (RFC 9002).  All durations are 0 until at least one
// round-trip has been measured.
type ConnStats struct {
	// MinRTT is the minimum RTT observed since the connection was established
	// (RFC 9002: min_rtt is a lower bound on the end-to-end RTT).
	MinRTT time.Duration
	// SmoothedRTT is an exponentially weighted moving average of RTT samples
	// (RFC 9002: smoothed_rtt).  Best metric for sustained connections.
	SmoothedRTT time.Duration
	// LatestRTT is the most recent RTT sample derived from an ACK frame
	// (RFC 9002: latest_rtt = ack_delay subtracted from send-to-ack time).
	LatestRTT time.Duration
	// MeanDeviation is the mean deviation of RTT samples (RFC 9002, §5.3).
	// It is initialised to zero and becomes non-zero only after the first
	// genuine ACK-based RTT sample arrives. Callers can use MeanDeviation == 0
	// as a reliable signal that no real measurement has been taken yet.
	MeanDeviation time.Duration
}

// Stream is a single bidirectional data channel over a Conn. The shape is
// io.ReadWriteCloser plus Reset, deliberately not QUIC-specific, so a
// non-QUIC implementation would wrap a net.Conn without changing this
// interface.
type Stream interface {
	io.ReadWriteCloser
	// Reset abruptly terminates both directions of the stream with the given
	// application error code — a QUIC stream reset. Unlike
	// Close (a clean FIN on the send side), Reset stays a reset.
	Reset(code uint64)
}

// Conn is an established transport connection that can carry multiple Streams.
type Conn interface {
	// OpenStream opens a new outbound bidirectional stream to the peer.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream blocks until the peer opens an inbound stream.
	AcceptStream(ctx context.Context) (Stream, error)
	// Stats returns current RTT statistics for this connection.
	Stats() ConnStats
	// HandshakeComplete returns a channel that is closed when the TLS
	// handshake finishes (1-RTT keys derived).
	HandshakeComplete() <-chan struct{}
	// Context returns the connection's lifecycle context; it is cancelled
	// when the connection is closed, with the close reason as the cause.
	Context() context.Context
	// CloseWithError closes the connection with an application-level error.
	CloseWithError(code uint64, msg string) error
	// PeerCertificates returns the verified peer certificate chain from the
	// completed TLS handshake (leaf first). Empty if the peer presented no
	// certificate. The agent derives the peer Identity from it.
	PeerCertificates() []*x509.Certificate
}

// Listener accepts inbound Conn connections.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Addr() net.Addr
	Close() error
}

// Transport establishes (Dial) and accepts (Listen) Conn connections.
type Transport interface {
	// Dial connects to the server at addr (host:port) and returns an
	// established Conn after the handshake completes.
	Dial(ctx context.Context, addr string) (Conn, error)
	// Listen starts accepting inbound connections on the transport's
	// pre-bound socket (address is determined by the concrete implementation).
	Listen() (Listener, error)
	// Close shuts down the transport, aborting pending operations.
	Close() error
}

// AppCloseCoder is implemented by the error a transport reports when the peer
// closed a connection with an application-level code. It exists so a caller can
// recognise a specific close reason without knowing which transport produced
// it, which keeps those checks working over the in-memory transport as well as
// over QUIC.
type AppCloseCoder interface {
	AppCloseCode() (uint64, bool)
}

// LocalAddrProvider is an optional interface implemented by transports that can
// report the local network address of their underlying socket. The dial loop
// uses it to log the UDP source 4-tuple on each attempt, which is essential for
// diagnosing NAT/CGNAT poisoning of a specific source port. Transports that do
// not implement this interface (e.g. the in-memory test transport) simply omit
// the local-address field from the log.
type LocalAddrProvider interface {
	// LocalAddr returns the local network address of the underlying socket.
	LocalAddr() net.Addr
}

// RemoteAddrProvider is an optional interface implemented by connections that
// can report the address at the other end.
//
// It answers a question the socket cannot. A socket that accepts both address
// families reports only that it accepts both, so for a connection that arrived
// rather than one this side opened, the socket says nothing about which family
// the peer actually used. The connection knows, because the address came off
// the packet that opened it.
//
// Like the local-address interface above, it is optional: a connection that has
// no network address — the in-memory one used in tests — simply does not
// implement it, and a caller must treat absence as "not known" rather than as
// an error. Note that a type embedding the Conn interface to override one method
// does not inherit this one, because an embedded interface only carries the
// methods it declares; such a wrapper reports absence, which is the safe way to
// be wrong.
type RemoteAddrProvider interface {
	// RemoteAddr returns the network address of the peer.
	RemoteAddr() net.Addr
}
