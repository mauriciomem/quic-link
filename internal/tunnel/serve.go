// Package tunnel wires together the transport layer and local TCP services.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
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

// serveConn derives the peer identity once (INV-3) and handles all streams on a
// single accepted QUIC connection.
func serveConn(ctx context.Context, conn transport.Conn, rtr *router.Router) {
	peer, err := router.IdentityFromCerts(conn.PeerCertificates())
	if err != nil {
		// No authenticated identity: refuse the whole connection.
		_ = conn.CloseWithError(0x02, "no peer identity")
		return
	}
	slog.Info("session established", "peer", peer.Short())
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Connection closed or ctx cancelled; stop accepting streams.
			return
		}
		go func() {
			if err := serveStream(ctx, stream, peer, rtr); err != nil {
				slog.Warn("stream handler error", "err", err)
			}
		}()
	}
}

// serveStream reads the protocol-v1 header, resolves and authorizes the target
// via rtr, writes a response frame, and on status 0 proxies the stream to the
// dialed connection. pipe() owns the lifetime of both stream and svc once
// splicing begins.
func serveStream(ctx context.Context, stream transport.Stream, peer router.Identity, rtr *router.Router) error {
	h, err := proto.ReadHeader(stream)
	if err != nil {
		return replyHeaderError(stream, err)
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
