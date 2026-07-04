// Package tunnel wires together the transport layer and local TCP services.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Serve accepts QUIC connections from ln and, for every stream opened by a
// client, dials serviceAddr over TCP and bidirectionally proxies data.
// It runs until ctx is cancelled or ln is closed.
func Serve(ctx context.Context, ln transport.Listener, serviceAddr string) error {
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
		go serveConn(ctx, conn, serviceAddr)
	}
}

// serveConn handles all streams on a single accepted QUIC connection.
func serveConn(ctx context.Context, conn transport.Conn, serviceAddr string) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Connection closed or ctx cancelled; stop accepting streams.
			return
		}
		go func() {
			if err := serveStream(ctx, stream, serviceAddr); err != nil {
				slog.Warn("stream handler error", "err", err)
			}
		}()
	}
}

// serveStream proxies a single QUIC stream to the TCP service at serviceAddr.
// pipe() owns the lifetime of both stream and svc.
func serveStream(ctx context.Context, stream transport.Stream, serviceAddr string) error {
	svc, err := (&net.Dialer{}).DialContext(ctx, "tcp", serviceAddr)
	if err != nil {
		// Close the stream so the client gets an error instead of hanging.
		stream.Close()
		// Distinguish service-unreachable from other errors for operators.
		return fmt.Errorf("service unreachable (%s): %w", serviceAddr, err)
	}
	start := time.Now()
	slog.Info("stream proxying to service", "service", serviceAddr)
	// pipe closes both stream and svc when done.
	pipe(stream, svc)
	slog.Info("stream closed",
		"service", serviceAddr,
		"duration", time.Since(start).Round(time.Millisecond),
	)
	return nil
}

// closeWrite half-closes the write side of c, propagating a clean EOF as a FIN.
// *net.TCPConn exposes CloseWrite(); a *quic.Stream's Close() already closes
// only the send direction, so Close() is the correct write-half-close for
// streams. It leaves the read side open so replies keep flowing.
func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// resetConn tears a connection down abruptly. A reset stays a reset —
// SetLinger(0) makes a TCP Close() emit RST. QUIC stream reset codes
// (02 §5.4, code 0x10) arrive with the framed protocol in Phase 1a and are
// intentionally out of scope here (ADR-0009).
func resetConn(c io.Closer) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
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
