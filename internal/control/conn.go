// Package control implements the quic-link control plane: gRPC (02 §6) served
// over the single per-session control stream. It provides the net.Conn adapter
// that lets gRPC run its HTTP/2 framing over one QUIC stream, a
// single-connection net.Listener for the agent-side gRPC server, and the
// server/client wiring for the Control service.
package control

import (
	"net"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// controlAddr is a placeholder net.Addr for a control stream. A control stream
// has no address of its own — it rides inside an established QUIC connection —
// but net.Conn requires Local/RemoteAddr, and gRPC logs them.
type controlAddr struct{}

func (controlAddr) Network() string { return "quic-link" }
func (controlAddr) String() string  { return "control" }

// deadliner is the optional deadline surface a transport.Stream may expose. The
// QUIC stream implements it natively (see internal/transport/quicStream); other
// implementations may not, in which case the adapter treats deadlines as no-ops.
type deadliner interface {
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// streamConn adapts a transport.Stream to net.Conn so gRPC can run its HTTP/2
// framing over a single QUIC stream (02 §6). Deadlines are delegated to the
// stream when it supports them; otherwise they are no-ops, which is safe
// because gRPC drives its own timeouts via context and keepalive PINGs.
type streamConn struct {
	s transport.Stream
}

// NewConn wraps a transport.Stream as a net.Conn.
func NewConn(s transport.Stream) net.Conn { return &streamConn{s: s} }

func (c *streamConn) Read(p []byte) (int, error)  { return c.s.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.s.Write(p) }
func (c *streamConn) Close() error                { return c.s.Close() }
func (c *streamConn) LocalAddr() net.Addr         { return controlAddr{} }
func (c *streamConn) RemoteAddr() net.Addr        { return controlAddr{} }

func (c *streamConn) SetDeadline(t time.Time) error {
	if d, ok := c.s.(deadliner); ok {
		return d.SetDeadline(t)
	}
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	if d, ok := c.s.(deadliner); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.s.(deadliner); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}
