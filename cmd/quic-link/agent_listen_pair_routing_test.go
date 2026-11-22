/**
 * @spec-handoff
 * @interface pairing.NewRoutedListener(ln, handle) wrapping the agentListenTransport listener built with identity.ListenTLSWithPairing(key, src, w.IsOpen); the real tunnel.Serve serves what it returns
 * @behavior
 *   - a connection that negotiated quic-link/pair1 is handled by the pairing handler and never reaches tunnel.Serve
 *   - a quic-link/1 connection reaches tunnel.Serve (a data stream is spliced to a local TCP sink) and never reaches the pairing handler
 *   - routing follows the NEGOTIATED protocol: a client offering both reaches the handler while the window is open and tunnel.Serve once it is closed
 *   - a test-only joiner (blob secret, exporter, proof, pairing frames) pairs once; the window then closes and a pair1-only offer fails at ALPN (remote 0x178)
 *   - every handshake goes through a QUIC Retry
 * @edge-cases
 *   - the spy is a recording transport.Listener between the routed listener and tunnel.Serve: it sees exactly the conns tunnel.Serve gets
 *   - nothing here is wired into the agent; cmd changes are tests only
 * @see ../../internal/pairing/route.go ../../internal/pairing/serve.go ./agent.go (agentListenTransport)
 */
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/pairing"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// negotiated names a conn's negotiated ALPN, or "<no ALPNProvider>".
func negotiated(c transport.Conn) string {
	if a, ok := c.(transport.ALPNProvider); ok {
		return a.NegotiatedProtocol()
	}
	return "<no ALPNProvider>"
}

// recordingListener records the negotiated ALPN of every conn its Accept
// returns, i.e. of every conn tunnel.Serve receives.
type recordingListener struct {
	transport.Listener
	mu     sync.Mutex
	protos []string
}

func (l *recordingListener) Accept(ctx context.Context) (transport.Conn, error) {
	c, err := l.Listener.Accept(ctx)
	if err == nil {
		l.mu.Lock()
		l.protos = append(l.protos, negotiated(c))
		l.mu.Unlock()
	}
	return c, err
}

func (l *recordingListener) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.protos...)
}

// pairPersistSpy records Persist calls.
type pairPersistSpy struct {
	mu   sync.Mutex
	pins []string
}

func (p *pairPersistSpy) Persist(pin, _ string, _ netip.AddrPort) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pins = append(p.pins, pin)
	return nil
}

func (p *pairPersistSpy) persisted() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.pins...)
}

// routedAgent is the composed agent listener under test.
type routedAgent struct {
	addr   string
	rec    *recordingListener
	sinkCh chan []byte

	mu      sync.Mutex
	handled []string // negotiated ALPN of every conn the pairing handler got
}

func (a *routedAgent) handledProtos() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.handled...)
}

func startRoutedAgent(t *testing.T, srvKey ed25519.PrivateKey, srvPin, steadyPin string, w *pairing.Window, p pairing.Persister) *routedAgent {
	t.Helper()
	src := func() map[string]struct{} { return map[string]struct{}{steadyPin: {}} }
	return startRoutedAgentFrom(t, srvKey, srvPin, src, w, p)
}

// startRoutedAgentFrom is startRoutedAgent with the steady AllowedSource
// supplied by the caller.
func startRoutedAgentFrom(t *testing.T, srvKey ed25519.PrivateKey, srvPin string, src func() map[string]struct{}, w *pairing.Window, p pairing.Persister) *routedAgent {
	t.Helper()
	a := &routedAgent{sinkCh: make(chan []byte, 8)}

	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	t.Cleanup(func() { sink.Close() })
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				n, _ := io.ReadAtLeast(c, b, 1)
				a.sinkCh <- b[:n]
			}()
		}
	}()

	conf, err := identity.ListenTLSWithPairing(srvKey, src, w.IsOpen)
	if err != nil {
		t.Fatalf("ListenTLSWithPairing: %v", err)
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("agent socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() })
	tr, err := agentListenTransport(sock, conf)
	if err != nil {
		t.Fatalf("agentListenTransport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	qln, err := tr.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	a.addr = qln.Addr().String()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	routed := pairing.NewRoutedListener(qln, func(ctx context.Context, c transport.Conn) {
		a.mu.Lock()
		a.handled = append(a.handled, negotiated(c))
		a.mu.Unlock()
		_ = pairing.Serve(ctx, c, w, p, log)
	})
	t.Cleanup(func() { routed.Close() })
	a.rec = &recordingListener{Listener: routed}

	rtr, err := router.New(map[string]string{"sink": "tcp://" + sink.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- tunnel.Serve(ctx, a.rec, rtr, tunnel.ServeOpts{OwnPin: srvPin}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("tunnel.Serve did not return after its ctx was cancelled")
		}
	})
	return a
}

// routedDial dials the agent with key, offering protos, over a socket that
// counts Retry packets.
func routedDial(t *testing.T, addr string, key ed25519.PrivateKey, srvPin string, protos ...string) (transport.Conn, int64, error) {
	t.Helper()
	base, err := identity.ClientDialTLS(key, srvPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	conf := base.Clone()
	conf.NextProtos = protos
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { udp.Close() })
	sniff := newRetrySniffConn(udp)
	tr, err := transport.NewQUICTransport(sniff, conf, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, addr)
	if err == nil {
		t.Cleanup(func() { c.CloseWithError(0, "test done") })
	}
	return c, sniff.retries.Load(), err
}

type readDeadliner interface{ SetReadDeadline(time.Time) error }

// tunnelToSink opens a tcp stream to the "sink" route and sends payload.
func tunnelToSink(c transport.Conn, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer s.Close()
	if d, ok := s.(readDeadliner); ok {
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	if err := proto.WriteHeader(s, proto.Header{Kind: proto.KindTCP, Target: "sink"}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	resp, err := proto.ReadResponse(s)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Status != proto.StatusOK {
		return fmt.Errorf("tunnel response %v %q, want ok", resp.Status, resp.Msg)
	}
	_, err = s.Write(payload)
	return err
}

// joinOnce is a test-only joiner exchange: it proves knowledge of secret over
// c's exporter and returns the listener's answer.
func joinOnce(c transport.Conn, secret []byte, label string) (pairing.PairResponse, error) {
	e, ok := c.(transport.EKMProvider)
	if !ok {
		return pairing.PairResponse{}, fmt.Errorf("client Conn %T has no EKMProvider", c)
	}
	ekm, err := e.ExportKeyingMaterial(pairing.EKMLabel, pairing.ExporterContext(label), pairing.EKMLength)
	if err != nil {
		return pairing.PairResponse{}, err
	}
	payload, err := pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: label, Proof: pairing.Proof(secret, ekm)}.Marshal()
	if err != nil {
		return pairing.PairResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.OpenStream(ctx)
	if err != nil {
		return pairing.PairResponse{}, fmt.Errorf("open stream: %w", err)
	}
	if d, ok := s.(readDeadliner); ok {
		_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	if err := pairing.WriteFrame(s, payload); err != nil {
		return pairing.PairResponse{}, fmt.Errorf("write request: %w", err)
	}
	raw, err := pairing.ReadFrame(s)
	if err != nil {
		return pairing.PairResponse{}, fmt.Errorf("read response: %w", err)
	}
	return pairing.ParsePairResponse(raw)
}

func TestAgentListenTransport_PairingAndSteadyAreSeparated(t *testing.T) {
	srvKey, steadyKey, srvPin, steadyPin := newSeamKeys(t)
	_, joinKey, _, joinPin := newSeamKeys(t)
	w, err := pairing.OpenWindow(srvPin, 0)
	if err != nil {
		t.Fatalf("OpenWindow: %v", err)
	}
	t.Cleanup(w.Close)
	blob, err := pairing.ParseBlob(w.Blob())
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}
	secret := blob.Secret()
	spy := &pairPersistSpy{}
	a := startRoutedAgent(t, srvKey, srvPin, steadyPin, w, spy)
	both := []string{seamPair1, transport.ALPN}

	wantSink := func(t *testing.T, want []byte) {
		t.Helper()
		select {
		case got := <-a.sinkCh:
			if !bytes.Equal(got, want) {
				t.Errorf("sink got %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("sink never received %q", want)
		}
	}

	t.Run("window open: quic-link/1 reaches the tunnel", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, steadyKey, srvPin, transport.ALPN)
		if err != nil {
			t.Fatalf("steady dial: %v", err)
		}
		wantSawRetry(t, retries)
		if err := tunnelToSink(c, []byte("steady-open")); err != nil {
			t.Fatalf("steady session: %v", err)
		}
		wantSink(t, []byte("steady-open"))
	})

	t.Run("window open: a client offering both negotiates pair1 and reaches the handler", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, steadyKey, srvPin, both...)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		wantSawRetry(t, retries)
		if got := negotiated(c); got != seamPair1 {
			t.Fatalf("negotiated %q, want %q while the window is open", got, seamPair1)
		}
		wrong := make([]byte, pairing.SecretLen)
		wrong[0] = 1
		resp, err := joinOnce(c, wrong, "wrong-secret")
		if err != nil {
			t.Errorf("pairing exchange: %v (the connection did not reach the pairing handler)", err)
		} else if resp.Status != pairing.StatusBadProof {
			t.Errorf("wrong secret answered %v, want bad_proof", resp.Status)
		}
	})

	t.Run("window open: a joiner pairs", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, joinKey, srvPin, seamPair1)
		if err != nil {
			t.Fatalf("joiner dial: %v", err)
		}
		wantSawRetry(t, retries)
		resp, err := joinOnce(c, secret[:], "joiner")
		if err != nil {
			t.Errorf("pairing exchange: %v (the connection did not reach the pairing handler)", err)
		} else if resp.Status != pairing.StatusOK {
			t.Errorf("valid proof answered %v, want ok", resp.Status)
		}
		if got := spy.persisted(); len(got) != 1 || got[0] != joinPin {
			t.Errorf("Persist got pins %q, want exactly the joiner's [%q]", got, joinPin)
		}
		if w.IsOpen() {
			t.Error("window still open after pairing")
		}
	})

	t.Run("window closed: a pair1-only offer fails at ALPN", func(t *testing.T) {
		_, retries, err := routedDial(t, a.addr, joinKey, srvPin, seamPair1)
		wantSawRetry(t, retries)
		var te *quic.TransportError
		if !errors.As(err, &te) || te.ErrorCode != 0x178 || !te.Remote {
			t.Errorf("pair1 dial with the window closed = %v, want remote TLS alert 0x178", err)
		}
	})

	t.Run("window closed: a client offering both negotiates quic-link/1 and reaches the tunnel", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, steadyKey, srvPin, both...)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		wantSawRetry(t, retries)
		if got := negotiated(c); got != transport.ALPN {
			t.Fatalf("negotiated %q, want %q with the window closed", got, transport.ALPN)
		}
		if err := tunnelToSink(c, []byte("steady-closed")); err != nil {
			t.Fatalf("steady session: %v", err)
		}
		wantSink(t, []byte("steady-closed"))
	})

	// What tunnel.Serve received, and what the pairing handler received.
	wantTunnel := []string{transport.ALPN, transport.ALPN}
	tunneled := a.rec.seen()
	if slices.Contains(tunneled, seamPair1) {
		t.Errorf("tunnel.Serve received connections negotiated as %q: a pair1 connection must never reach it", tunneled)
	}
	if !slices.Equal(tunneled, wantTunnel) {
		t.Errorf("tunnel.Serve received connections negotiated as %q, want %q (both quic-link/1 connections)", tunneled, wantTunnel)
	}
	got := a.handledProtos()
	if slices.Contains(got, transport.ALPN) {
		t.Errorf("the pairing handler received connections negotiated as %q: a quic-link/1 connection must never reach it", got)
	}
	if wantHandler := []string{seamPair1, seamPair1}; !slices.Equal(got, wantHandler) {
		t.Errorf("the pairing handler received connections negotiated as %q, want %q (both pair1 connections)", got, wantHandler)
	}
}
