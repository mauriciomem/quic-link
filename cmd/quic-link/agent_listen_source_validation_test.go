package main

// agent_listen_source_validation_test.go checks that the socket the agent
// listens on makes a connecting peer prove it can receive at the address it
// claims, using a QUIC Retry (RFC 9000 section 8.1), before any handshake state
// is kept for that peer.
//
// The agent's listening socket accepts datagrams from anywhere, including from
// spoofed source addresses. Without Retry, each forged Initial packet makes the
// agent allocate handshake state and reply to the forged address, which turns
// the agent into a reflector and lets a flood of forged sources exhaust it.
// Handshake success alone cannot show the protection exists: a handshake
// completes just the same with or without a Retry. So the test watches the wire
// from the client side and requires an actual Retry packet to have arrived
// before the handshake completed.
//
// @spec-handoff
// @interface agentListenTransport(conn net.PacketConn, tlsConf *tls.Config) (*transport.QUICTransport, error)
// @behavior
//   - The transport it returns, once listening, answers a client's first
//     Initial packet with a Retry packet (long header, QUIC v1, type bits
//     0xf0 on the first byte) rather than starting the handshake directly.
//   - The client then retries with the supplied token and the handshake
//     completes, so a legitimate peer still gets through.
//   - A plain transport.NewQUICTransport listener, used as a control, does NOT
//     send a Retry: its first inbound datagram is an Initial (0xc0). That
//     keeps the Retry check from passing vacuously.
// @edge-cases
//   - The sniffer wraps the net.PacketConn interface, not *net.UDPConn,
//     because quic-go reads a *net.UDPConn through an out-of-band path that
//     would bypass the wrapper and leave every counter at zero.
//   - Retry is recognised by first byte &0xf0 == 0xf0 with version field 1;
//     a handshake that completes with zero Retry packets seen is a failure.
// @see ../../internal/transport/quic_transport.go (NewQUICListenTransport)
//
// Observed red before the listening transport performed source validation
// (quic-go v0.65.0, go1.26.10, -race):
//
//	--- FAIL: TestAgentListenTransport_PerformsRetrySourceValidation/production_helper
//	    agentListenTransport: first datagram from listener has type bits 0xc0
//	    (want 0xf0 Retry); Retry packets seen 0 of 2 inbound - listening
//	    transport performs no QUIC source-address validation
//	    agentListenTransport: saw 0 Retry packets of 2 inbound (want >= 1) - ...
//	--- PASS: .../control_plain_NewQUICTransport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// quicV1 is the QUIC version number carried in the long header of every
// version 1 packet, Retry included.
const quicV1 = 1

// retrySniffConn wraps a packet socket and records what arrives on it, without
// altering anything. It embeds the net.PacketConn interface on purpose: embedding
// *net.UDPConn instead would expose its ReadMsgUDP method, quic-go would take
// that path, and ReadFrom here would never be called.
type retrySniffConn struct {
	net.PacketConn

	inbound  atomic.Int64 // datagrams read
	retries  atomic.Int64 // datagrams that are a QUIC v1 Retry packet
	first    atomic.Int64 // first byte of the first long-header datagram, -1 if none yet
	firstVer atomic.Int64 // version of that datagram, -1 if none yet
}

func newRetrySniffConn(c net.PacketConn) *retrySniffConn {
	s := &retrySniffConn{PacketConn: c}
	s.first.Store(-1)
	s.firstVer.Store(-1)
	return s
}

func (c *retrySniffConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.inbound.Add(1)
		b := p[:n]
		if b[0]&0x80 != 0 && n >= 5 { // long header: first byte then 4-byte version
			ver := int64(binary.BigEndian.Uint32(b[1:5]))
			if c.first.CompareAndSwap(-1, int64(b[0])) {
				c.firstVer.Store(ver)
			}
			if b[0]&0xF0 == 0xF0 && ver == quicV1 {
				c.retries.Add(1)
			}
		}
	}
	return n, addr, err
}

// sniffResult is what the client's socket saw during one handshake.
type sniffResult struct {
	completed bool
	inbound   int64
	retries   int64
	first     int64
	firstVer  int64
}

// retryHandshake completes one handshake between a client, whose socket is
// watched, and a listener built by newServer, and reports what the client's
// socket received. It calls t.Fatalf if the handshake does not complete: with
// no handshake there is nothing meaningful to say about Retry.
func retryHandshake(
	t *testing.T,
	newServer func(net.PacketConn, *tls.Config) (*transport.QUICTransport, error),
) sniffResult {
	t.Helper()

	agentKey, agentPin := stdioAuthGenIdentity(t)
	clientKey, clientPin := stdioAuthGenIdentity(t)

	serverTLS, err := identity.AgentListenTLS(agentKey, []string{clientPin})
	if err != nil {
		t.Fatalf("agent TLS: %v", err)
	}
	clientTLS, err := identity.ClientDialTLS(clientKey, agentPin)
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	// Cleanups run last-registered first: connections and the context go
	// first, then the listener, the transports, and the sockets last.
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		cancel()
		t.Fatalf("agent socket: %v", err)
	}
	t.Cleanup(func() { serverUDP.Close() })
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		cancel()
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { clientUDP.Close() })
	sniff := newRetrySniffConn(clientUDP)

	serverTr, err := newServer(serverUDP, serverTLS)
	if err != nil {
		cancel()
		t.Fatalf("agent transport: %v", err)
	}
	t.Cleanup(func() { serverTr.Close() })
	clientTr, err := transport.NewQUICTransport(sniff, clientTLS, nil)
	if err != nil {
		cancel()
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { clientTr.Close() })

	ln, err := serverTr.Listen()
	if err != nil {
		cancel()
		t.Fatalf("agent listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type accepted struct {
		conn transport.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		c, err := ln.Accept(ctx)
		acceptCh <- accepted{c, err}
	}()

	var serverConn, clientConn transport.Conn
	t.Cleanup(func() {
		cancel() // unblocks Accept if the dial never reached it
		<-acceptDone
		if clientConn != nil {
			clientConn.CloseWithError(0, "test done")
		}
		if serverConn != nil {
			serverConn.CloseWithError(0, "test done")
		}
	})

	clientConn, err = clientTr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}

	select {
	case a := <-acceptCh:
		if a.err != nil {
			t.Fatalf("accept: %v", a.err)
		}
		serverConn = a.conn
	case <-ctx.Done():
		t.Fatalf("listener never accepted the connection: %v", ctx.Err())
	}

	completed := true
	for _, c := range []transport.Conn{clientConn, serverConn} {
		select {
		case <-c.HandshakeComplete():
		case <-ctx.Done():
			completed = false
		}
	}
	if !completed {
		t.Fatalf("handshake did not complete within the deadline: %v", ctx.Err())
	}

	return sniffResult{
		completed: completed,
		inbound:   sniff.inbound.Load(),
		retries:   sniff.retries.Load(),
		first:     sniff.first.Load(),
		firstVer:  sniff.firstVer.Load(),
	}
}

func TestAgentListenTransport_PerformsRetrySourceValidation(t *testing.T) {
	t.Run("production_helper", func(t *testing.T) {
		r := retryHandshake(t, agentListenTransport)

		if r.inbound <= 0 {
			t.Errorf("agentListenTransport: the client socket received no datagrams, so nothing was observed")
		}
		if r.firstVer != quicV1 {
			t.Errorf("agentListenTransport: first long-header datagram from listener has version %d (want %d)", r.firstVer, quicV1)
		}
		if r.first&0xF0 != 0xF0 {
			t.Errorf("agentListenTransport: first datagram from listener has type bits 0x%x (want 0xf0 Retry); "+
				"Retry packets seen %d of %d inbound - listening transport performs no QUIC source-address validation",
				r.first&0xF0, r.retries, r.inbound)
		}
		if r.retries < 1 {
			t.Errorf("agentListenTransport: saw %d Retry packets of %d inbound (want >= 1) - "+
				"listening transport performs no QUIC source-address validation", r.retries, r.inbound)
		}
	})

	// The control is a listener known not to ask for a Retry. If the detector
	// were blind (counters stuck at zero, or every packet misread), the first
	// subtest could pass or fail for the wrong reason; here the detector must
	// positively see an Initial and no Retry.
	t.Run("control_plain_NewQUICTransport", func(t *testing.T) {
		r := retryHandshake(t, func(c net.PacketConn, tc *tls.Config) (*transport.QUICTransport, error) {
			return transport.NewQUICTransport(c, tc, nil)
		})

		if r.inbound <= 0 {
			t.Errorf("control: the client socket received no datagrams, so the detector is blind")
		}
		if r.firstVer != quicV1 {
			t.Errorf("control: first long-header datagram has version %d (want %d)", r.firstVer, quicV1)
		}
		if r.first&0xF0 != 0xC0 {
			t.Errorf("control: first datagram has type bits 0x%x (want 0xc0 Initial)", r.first&0xF0)
		}
		if r.retries != 0 {
			t.Errorf("control: saw %d Retry packets from a listener that does no source validation (want 0)", r.retries)
		}
	})
}
