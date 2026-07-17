// Package tunnel wires together the transport layer and local TCP services.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
)

const (
	// controlOpenDeadline bounds how long after a session is established the
	// client may take to open its control stream. Past it, the agent closes
	// the session with 0x03.
	controlOpenDeadline = 5 * time.Second
	// agentVersionMsg is carried in the control stream's ok response.
	// TODO: replace with the build version once it is wired through.
	agentVersionMsg = "quic-link agent"
)

// Serve accepts QUIC connections from ln and, for every stream opened by a
// client, reads a protocol-v1 header, resolves and authorizes the named target
// through rtr, replies with a response frame, and (on success) bidirectionally
// proxies data to the resolved address. It runs until ctx is cancelled or ln
// is closed.
func Serve(ctx context.Context, ln transport.Listener, rtr *router.Router) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go serveConn(ctx, conn, rtr)
	}
}

// serveConn derives the peer identity once and handles all streams on a
// single accepted QUIC connection. It also enforces the control-stream open
// deadline: if the client does not open a control stream within
// controlOpenDeadline, the session is closed with 0x03.
func serveConn(ctx context.Context, conn transport.Conn, rtr *router.Router) {
	peer, err := router.IdentityFromCerts(conn.PeerCertificates())
	if err != nil {
		// Should be unreachable: the pinning handshake already requires a client
		// certificate, so a peer without one never completes a connection. Kept
		// as defense-in-depth.
		_ = conn.CloseWithError(0x02, "no peer identity")
		return
	}
	slog.Info("session established", "peer", peer.Short())

	cs := &controlState{}
	openTimer := time.AfterFunc(controlOpenDeadline, func() {
		if !cs.isOpen() {
			_ = conn.CloseWithError(0x03, "control stream not opened within deadline")
		}
	})
	defer openTimer.Stop()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Connection closed or ctx cancelled; stop accepting streams.
			return
		}
		go func() {
			if err := serveStream(ctx, conn, stream, peer, rtr, cs, openTimer); err != nil {
				slog.Warn("stream handler error", "err", err)
			}
		}()
	}
}

// serveStream reads the protocol-v1 header and dispatches: a control stream to
// serveControl, otherwise a data stream resolved and authorized via rtr, then
// on status 0 spliced to the dialed connection. pipe() owns the lifetime of
// both stream and svc once splicing begins.
func serveStream(
	ctx context.Context,
	conn transport.Conn,
	stream transport.Stream,
	peer router.Identity,
	rtr *router.Router,
	cs *controlState,
	openTimer *time.Timer,
) error {
	h, err := proto.ReadHeader(stream)
	if err != nil {
		return replyHeaderError(stream, err)
	}

	if h.Kind == proto.KindControl {
		return serveControl(ctx, conn, stream, peer, h, cs, openTimer)
	}

	svc, err := rtr.Dial(ctx, peer, h)
	if err != nil {
		return replyDialError(stream, h, err)
	}

	if err := proto.WriteResponse(stream, proto.Response{Status: proto.StatusOK}); err != nil {
		_ = svc.Close()
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("write ok response: %w", err)
	}

	start := time.Now()
	slog.Info("stream proxying to service", "peer", peer.Short(), "target", h.Target)
	// pipe closes both stream and svc when done.
	pipe(stream, svc)
	slog.Info("stream closed",
		"peer", peer.Short(),
		"target", h.Target,
		"duration", time.Since(start).Round(time.Millisecond),
	)
	return nil
}

// serveControl handles the single per-session control stream: it
// validates the control proto version, enforces exactly-one-per-session, replies
// ok, and then serves gRPC until the stream closes — at which point the whole
// session is torn down (control-stream closure is session death).
func serveControl(
	ctx context.Context,
	conn transport.Conn,
	stream transport.Stream,
	peer router.Identity,
	h proto.Header,
	cs *controlState,
	openTimer *time.Timer,
) error {
	if h.Meta["proto"] != "1" {
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnsupportedVersion,
			Msg:    `control proto must be "1"`,
		})
		_ = stream.Close()
		_ = conn.CloseWithError(0x04, "unsupported control proto")
		return nil
	}
	if !cs.markOpen() {
		// A control stream is already open on this session.
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusBadHeader,
			Msg:    "control stream already open",
		})
		_ = stream.Close()
		return nil
	}
	openTimer.Stop()

	if err := proto.WriteResponse(stream, proto.Response{Status: proto.StatusOK, Msg: agentVersionMsg}); err != nil {
		stream.Reset(proto.StreamResetCode)
		_ = conn.CloseWithError(0x03, "control response write failed")
		return fmt.Errorf("control: write ok: %w", err)
	}

	slog.Info("control stream opened", "peer", peer.Short())
	// Serve gRPC until the control stream dies; then the session is dead.
	_ = control.Serve(ctx, stream)
	slog.Info("control stream closed; tearing down session", "peer", peer.Short())
	_ = conn.CloseWithError(0x00, "control stream closed")
	return nil
}

// controlState tracks whether this session's one-per-session control stream has
// been opened, so the open deadline can be cancelled and a duplicate refused.
type controlState struct {
	mu   sync.Mutex
	open bool
}

// markOpen records the control stream as open, returning true only the first
// time (a second call — a duplicate control stream — returns false).
func (c *controlState) markOpen() (firstTime bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		return false
	}
	c.open = true
	return true
}

func (c *controlState) isOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.open
}

// replyDialError maps a router.Dial failure to the protocol response and
// returns an error for logging. Expected refusals (unknown target,
// unauthorized) return nil so they do not log loudly; a genuine dial failure is
// wrapped and returned.
func replyDialError(stream transport.Stream, h proto.Header, err error) error {
	switch {
	case errors.Is(err, router.ErrUnknownTarget):
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnknownTarget,
			Msg:    fmt.Sprintf("no target %q", h.Target),
		})
		_ = stream.Close()
		return nil
	case errors.Is(err, router.ErrUnauthorized):
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnauthorized,
			Msg:    fmt.Sprintf("not authorized for %q", h.Target),
		})
		_ = stream.Close()
		return nil
	default:
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusDialFailed,
			Msg:    err.Error(),
		})
		_ = stream.Close()
		return fmt.Errorf("dial target %q: %w", h.Target, err)
	}
}

// replyHeaderError maps a header read/parse failure to the protocol behavior
// and returns the error for logging.
func replyHeaderError(stream transport.Stream, err error) error {
	switch {
	case errors.Is(err, proto.ErrFrameTooLarge):
		// Oversized frame: reset the stream, send no response.
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("header: %w", err)
	case errors.Is(err, proto.ErrUnsupportedVersion):
		// Unsupported version: acceptor replies status 6.
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnsupportedVersion,
			Msg:    "unsupported protocol version; rebuild the client",
		})
		_ = stream.Close()
		return fmt.Errorf("header: %w", err)
	case errors.Is(err, proto.ErrBadHeader):
		// Malformed or missing header fields: status 5.
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusBadHeader,
			Msg:    err.Error(),
		})
		_ = stream.Close()
		return fmt.Errorf("header: %w", err)
	default:
		// I/O error before a full header arrived (e.g. peer vanished).
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("read header: %w", err)
	}
}

// closeWrite half-closes the write side of c, propagating a clean EOF as a FIN.
// *net.TCPConn and *net.UnixConn expose CloseWrite(); a transport.Stream's
// Close() closes only its send direction, so Close() is the correct
// write-half-close for streams.
func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// resetConn tears a connection down abruptly (a reset stays a reset).
// SetLinger(0) makes a TCP Close() emit RST; a transport.Stream is reset with
// the QUIC stream reset code. A unix socket has no RST, so the default plain
// Close() is the closest equivalent.
func resetConn(c io.Closer) {
	switch v := c.(type) {
	case *net.TCPConn:
		_ = v.SetLinger(0)
		_ = v.Close()
	case transport.Stream:
		v.Reset(proto.StreamResetCode)
	default:
		_ = c.Close()
	}
}

// pipe bidirectionally copies between a and b. A clean EOF in one direction
// becomes a write-half-close on the peer so the other direction keeps
// flowing — this is what lets scp, git, and request/response protocols finish
// instead of truncating. Both ends are fully released only after both
// directions complete.
func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		if _, err := io.Copy(b, a); err != nil {
			resetConn(b) // abrupt failure: reset, don't FIN
		} else {
			closeWrite(b) // clean EOF from a: no more writes are coming to b
		}
		done <- struct{}{}
	}()
	go func() {
		if _, err := io.Copy(a, b); err != nil {
			resetConn(a)
		} else {
			closeWrite(a)
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	// Both directions finished; release resources (idempotent; errors ignored).
	_ = a.Close()
	_ = b.Close()
}
