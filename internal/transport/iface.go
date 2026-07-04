// Package transport defines the Transport abstraction used by quic-link.
// The QUIC implementation is the only concrete implementation shipped today.
// See the TODO markers for TCP/wss fallback extension points.
package transport

import (
	"context"
	"io"
	"net"
	"time"
)

// ALPN is the TLS Application-Layer Protocol Negotiation identifier for
// Phase 0 (frameless streams, pre-protocol). Both client and server MUST
// include this in tls.Config.NextProtos. "quic-link/1" is reserved for the
// framed protocol v1 introduced in Phase 1a (ADR-0009).
const ALPN = "quic-link/0"

// ConnStats holds RTT measurements derived from the QUIC loss-detection
// machinery (RFC 9002 §5).  All durations are 0 until at least one
// round-trip has been measured.
type ConnStats struct {
	// MinRTT is the minimum RTT observed since the connection was established
	// (RFC 9002 §5.2: min_rtt is a lower bound on the end-to-end RTT).
	MinRTT time.Duration
	// SmoothedRTT is an exponentially weighted moving average of RTT samples
	// (RFC 9002 §5.3: smoothed_rtt).  Best metric for sustained connections.
	SmoothedRTT time.Duration
	// LatestRTT is the most recent RTT sample derived from an ACK frame
	// (RFC 9002 §5.1: latest_rtt = ack_delay subtracted from send-to-ack time).
	LatestRTT time.Duration
}

// Stream is a single bidirectional data channel over a Conn.
//
// TODO (TCP/wss fallback): implement Stream backed by a net.Conn, presenting
// the whole TCP connection as one stream.
type Stream interface {
	io.ReadWriteCloser
}

// Conn is an established transport connection that can carry multiple Streams.
//
// TODO (TCP/wss fallback): implement Conn backed by a net.Conn, exposing
// a single Stream wrapping the underlying TCP connection.
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
}

// Listener accepts inbound Conn connections.
//
// TODO (TCP/wss fallback): wrap net.Listener to implement this interface.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Addr() net.Addr
	Close() error
}

// Transport establishes (Dial) and accepts (Listen) Conn connections.
//
// TODO (TCP/wss fallback): implement Transport using net.Dial/net.Listen
// and register it behind a --transport=tcp flag in cmd/quic-link/main.go.
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
