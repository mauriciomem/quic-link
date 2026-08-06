package edge

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/names"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

const (
	// peekDeadline bounds how long a connection may take to say where it is
	// going. The size limit alone is not enough: a client that sends one byte a
	// minute never exceeds it and never finishes either.
	peekDeadline = 10 * time.Second

	// maxInFlightPeeks bounds how many connections can be mid-decision at once.
	// A browser opening a page makes many connections at once, so this is well
	// above what one page needs; the point is that a refusal is legible where
	// unbounded growth is not.
	maxInFlightPeeks = 256
)

// NameResolver turns the host a client asked for into the server that serves
// it. It is the security boundary of this edge: a host it refuses never reaches
// a session.
type NameResolver interface {
	Route(rawHost string) (server, service, host string, err error)
}

// peeker reads enough of a connection to learn where it is going, returning
// those bytes so they can be passed on unchanged.
type peeker interface {
	// name returns the host the connection asked for, along with every byte
	// consumed to find it. It returns a nil host when more bytes are needed.
	name(buf []byte) (host string, consumed int, err error)
	kind() string
}

// HostEdge is one listener shared by every server. Which server a connection
// belongs to is decided per connection, from the name the client asked for,
// because that name is inside the request rather than implied by the port it
// arrived on.
type HostEdge struct {
	ln   net.Listener
	zone NameResolver
	src  ConnSource
	pk   peeker

	wg  sync.WaitGroup
	sem chan struct{}
}

// NewHostEdge starts an edge on an already-bound listener.
func NewHostEdge(ctx context.Context, ln net.Listener, zone NameResolver, src ConnSource, pk peeker) *HostEdge {
	e := &HostEdge{ln: ln, zone: zone, src: src, pk: pk, sem: make(chan struct{}, maxInFlightPeeks)}
	e.wg.Add(1)
	go e.acceptLoop(ctx)
	return e
}

// Close stops accepting and waits for everything in flight.
func (e *HostEdge) Close() {
	_ = e.ln.Close()
	e.wg.Wait()
}

func (e *HostEdge) acceptLoop(ctx context.Context) {
	defer e.wg.Done()

	done := make(chan struct{})
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		select {
		case <-ctx.Done():
			_ = e.ln.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		conn, err := e.ln.Accept()
		if err != nil {
			return
		}
		select {
		case e.sem <- struct{}{}:
		default:
			_ = conn.Close()
			slog.Warn("edge: too many connections deciding where to go; refusing",
				"role", "daemon", "kind", e.pk.kind())
			continue
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() { <-e.sem }()
			e.handle(ctx, conn)
		}()
	}
}

// handle reads far enough to learn the destination, checks it, and hands the
// connection on with the bytes already read.
func (e *HostEdge) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	rawHost, prefix, err := e.peek(conn)
	if err != nil {
		// Nothing is opened. A connection that cannot say where it is going,
		// or says somewhere we do not serve, is simply cut: it never becomes a
		// stream, so nothing on the other side ever learns it was attempted.
		slog.Debug("edge: refusing a connection", "role", "daemon",
			"kind", e.pk.kind(), "err", err)
		return
	}

	server, service, host, err := e.zone.Route(rawHost)
	if err != nil {
		slog.Debug("edge: refusing a name we do not serve", "role", "daemon",
			"kind", e.pk.kind(), "err", err)
		return
	}

	octx, cancel := context.WithTimeout(ctx, openConnReadyTimeout)
	poolConn, pinPrefix, err := e.src.OpenConn(octx, server)
	cancel()
	if err != nil {
		slog.Warn("edge: no session for the server that name belongs to",
			"role", "daemon", "kind", e.pk.kind(), "server", server, "host", host, "err", err)
		return
	}

	reqid := tunnel.NewReqID()
	start := time.Now()
	tunnel.LogAttach(server, host, reqid, pinPrefix, start, false)
	defer tunnel.LogAttach(server, host, reqid, pinPrefix, start, true)
	slog.Debug("edge: routing by name", "role", "daemon",
		"kind", e.pk.kind(), "server", server, "service", service, "host", host, "reqid", reqid)

	if err := tunnel.DoAttachHTTP(ctx, poolConn, conn, host, reqid, prefix, nil); err != nil {
		slog.Debug("edge: splice ended", "role", "daemon", "host", host, "err", err)
	}
}

// peek reads until the destination is known, the size limit is reached, or the
// deadline passes. Everything read is returned, so nothing the client sent is
// lost — the bytes are handed on unchanged rather than reconstructed.
//
// It reads whatever has arrived rather than waiting for a fixed amount. A
// request is small and the client will not send more until it has an answer,
// so asking for a round number of bytes would wait for data that is never
// coming.
func (e *HostEdge) peek(conn net.Conn) (host string, prefix []byte, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(peekDeadline)); err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 0, 2048)
	chunk := make([]byte, 2048)
	for {
		n, rerr := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			host, consumed, herr := e.pk.name(buf)
			if herr != nil {
				return "", nil, herr
			}
			if consumed > 0 {
				return host, buf, nil
			}
			if len(buf) >= names.MaxHeaderBytes {
				return "", nil, errors.New("edge: the request never said where it was going")
			}
		}
		if rerr != nil {
			return "", nil, rerr
		}
	}
}
