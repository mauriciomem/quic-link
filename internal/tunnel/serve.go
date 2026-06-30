// Package tunnel wires together the transport layer and local TCP services.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

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
				slog.Debug("stream handler error", "err", err)
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
	// pipe closes both stream and svc when done.
	pipe(stream, svc)
	return nil
}

// pipe bidirectionally copies between a and b, closing each side's write
// direction when the other side signals EOF.  It blocks until both directions
// are complete.
func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a) //nolint:errcheck
		// Signal b that no more data is coming from a.
		b.Close() //nolint:errcheck
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b) //nolint:errcheck
		// Signal a that no more data is coming from b.
		a.Close() //nolint:errcheck
		done <- struct{}{}
	}()
	<-done
	<-done
}
