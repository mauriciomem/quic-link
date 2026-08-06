package names

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	// udpReadBuffer is the largest query we will look at. Queries are tiny; the
	// only reason this is not smaller is that a resolver may attach an options
	// record advertising a bigger buffer. Anything longer is truncated by the
	// kernel and will fail to parse, which is the correct outcome.
	udpReadBuffer = 1232

	// tcpMaxMessage caps what we will allocate for one query. The length prefix
	// allows 65535, but no legitimate query comes close, and honouring a large
	// declared length is how a handful of connections turn into a memory
	// problem.
	tcpMaxMessage = 4096

	// tcpIdleTimeout bounds a connection that has stopped talking, whether it
	// stalled halfway through a length prefix or simply opened and said nothing.
	tcpIdleTimeout = 5 * time.Second

	// tcpMaxConns bounds how many queries can be in flight over the stream
	// transport at once. A refusal is legible; unbounded goroutines are not.
	tcpMaxConns = 32

	// tcpMaxQueriesPerConn stops one connection cycling forever. Resolvers do
	// reuse a connection for a few queries, so this is not one.
	tcpMaxQueriesPerConn = 64
)

// Server answers DNS queries for one zone over both transports.
//
// It holds sockets that were bound elsewhere and handed to it, so that there is
// one place in the program where ports are taken and one answer to "what is
// this process listening on".
type Server struct {
	zone *Zone
	udp  net.PacketConn
	tcp  net.Listener

	wg  sync.WaitGroup
	sem chan struct{}
}

// NewServer starts serving on the given sockets and returns immediately.
// Either socket may be nil, in which case that transport is simply not served.
// Close stops everything and waits.
func NewServer(ctx context.Context, z *Zone, udp net.PacketConn, tcp net.Listener) *Server {
	s := &Server{zone: z, udp: udp, tcp: tcp, sem: make(chan struct{}, tcpMaxConns)}
	if udp != nil {
		s.wg.Add(1)
		go s.serveUDP(ctx)
	}
	if tcp != nil {
		s.wg.Add(1)
		go s.serveTCP(ctx)
	}
	return s
}

// Close stops both loops and waits for every goroutine to finish.
func (s *Server) Close() {
	if s.udp != nil {
		_ = s.udp.Close()
	}
	if s.tcp != nil {
		_ = s.tcp.Close()
	}
	s.wg.Wait()
}

// watch closes c when ctx ends, so a read blocked in the kernel comes back.
// Closing the socket is the only way to interrupt one; a deadline would mean
// waking up repeatedly to ask whether it is time to stop yet.
//
// The returned function must be called when the loop exits, so this goroutine
// does not outlive it.
func (s *Server) watch(ctx context.Context, c io.Closer) func() {
	done := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// serveUDP reads and answers datagrams one at a time.
//
// Deliberately no goroutine per query: there is nothing to overlap. An answer
// is computed from a fixed table with no I/O in the middle, so a goroutine
// would buy no concurrency and would hand an unbounded fan-out to anything that
// can send packets to a loopback port.
func (s *Server) serveUDP(ctx context.Context) {
	defer s.wg.Done()
	defer s.watch(ctx, s.udp)()

	buf := make([]byte, udpReadBuffer)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			return // the socket was closed: this is how shutdown arrives
		}
		reply, drop := Respond(buf[:n], s.zone)
		if drop {
			continue
		}
		if _, err := s.udp.WriteTo(reply, addr); err != nil {
			// A failed write to loopback means the socket is going away.
			return
		}
	}
}

// serveTCP accepts connections and answers length-prefixed queries on each.
func (s *Server) serveTCP(ctx context.Context) {
	defer s.wg.Done()
	defer s.watch(ctx, s.tcp)()

	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		default:
			// At the cap. Closing is a clear answer; queueing would only move
			// the problem somewhere with less visibility.
			_ = conn.Close()
			slog.Warn("names: too many DNS connections at once; refusing", "role", "daemon")
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.serveConn(conn)
		}()
	}
}

// serveConn answers queries on one connection until it goes quiet, misbehaves,
// or has had its turn.
func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()

	var lenBuf [2]byte
	for range tcpMaxQueriesPerConn {
		// The deadline covers a whole exchange and is reset for the next one,
		// so a connection is only killed for going silent, never for being slow
		// across many queries.
		if err := conn.SetDeadline(time.Now().Add(tcpIdleTimeout)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return // clean end of stream, or the deadline fired
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 || msgLen > tcpMaxMessage {
			// Refuse before allocating: the length is the attacker's to choose.
			return
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		reply, drop := Respond(msg, s.zone)
		if drop {
			// Nothing sensible to say, and unlike a datagram there is a
			// connection to tidy up.
			return
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(reply)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}
