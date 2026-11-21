/**
 * @spec-handoff
 * @interface transport.ALPNProvider { NegotiatedProtocol() string }  // implemented by the QUIC Conn, not by transport/mem
 * @interface transport.EKMProvider { ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) }
 * @behavior
 *   - real loopback QUIC through agentListenTransport (a Retry is seen on every handshake):
 *     both ends' Conn report the negotiated ALPN - quic-link/1 on the steady branch, quic-link/pair1 with the window open
 *   - the listener's Conn exports keying material equal to the raw client's for the same label and context,
 *     different for another context or another label
 *   - input-shape check (green from the start, it pins the inputs the pairing classifier keys on):
 *     closed window -> remote TransportError 0x178 at dial; joiner pinned to another key -> local 0x12a at dial;
 *     listener refusing the joiner's certificate -> dial succeeds, remote 0x12a on the first read and as context.Cause;
 *     a steady wrong-pin dial is still an auth failure
 * @edge-cases
 *   - the in-memory Conn implements neither provider (a caller must treat absence as "unknown")
 *   - the refusing pairing config is built by the test: the shipped one admits any parsable leaf
 * @see ../../internal/transport/quic_transport.go
 */
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// pairEKMLabel is the exporter label the pairing proof binds to.
const pairEKMLabel = "EXPERIMENTAL-quic-link-pairing-v1"

// pairSeam holds one server identity, one client identity and the configs a
// pairing-capable agent listener is built from.
type pairSeam struct {
	srvKey, cliKey   ed25519.PrivateKey
	srvPin, otherPin string
	steady, pairing  *tls.Config
}

func newPairSeam(t *testing.T) *pairSeam {
	t.Helper()
	srvKey, cliKey, srvPin, cliPin := newSeamKeys(t)
	_, _, otherPin, _ := newSeamKeys(t)
	steady, err := identity.AgentListenTLS(srvKey, []string{cliPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	pairing, err := identity.PairingTLS(srvKey)
	if err != nil {
		t.Fatalf("PairingTLS: %v", err)
	}
	return &pairSeam{srvKey: srvKey, cliKey: cliKey, srvPin: srvPin, otherPin: otherPin, steady: steady, pairing: pairing}
}

// listener is the outer config of a pairing-capable agent listener serving
// pairingConf while open is true.
func (p *pairSeam) listener(t *testing.T, pairingConf *tls.Config, open bool) *tls.Config {
	t.Helper()
	outer, err := identity.ListenTLSWithPairingConfig(func() (*tls.Config, error) { return p.steady, nil }, pairingConf, func() bool { return open })
	if err != nil {
		t.Fatalf("ListenTLSWithPairingConfig: %v", err)
	}
	return outer
}

// client is a client config pinned to pin that offers exactly protos.
func (p *pairSeam) client(t *testing.T, pin string, protos ...string) *tls.Config {
	t.Helper()
	base, err := identity.ClientDialTLS(p.cliKey, pin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	c := base.Clone()
	c.NextProtos = protos
	return c
}

// rawRetryDial is one dial by a raw quic-go client over a watched socket
// against a listener built by newServer; it never requires the handshake to
// succeed, so refusals can be inspected.
type rawRetryDial struct {
	rig     *retryRig
	conn    *quic.Conn
	err     error
	retries int64
}

func retryRawDial(
	t *testing.T,
	newServer func(net.PacketConn, *tls.Config) (*transport.QUICTransport, error),
	serverTLS, clientTLS *tls.Config,
) rawRetryDial {
	t.Helper()
	rig := newRetryRig(t, newServer, serverTLS)
	tr := &quic.Transport{Conn: rig.sniff}
	t.Cleanup(func() { tr.Close() })
	ctx, cancel := context.WithTimeout(rig.ctx, 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, rig.addr, clientTLS, nil)
	if err == nil {
		t.Cleanup(func() { conn.CloseWithError(0, "test done") })
	}
	return rawRetryDial{rig: rig, conn: conn, err: err, retries: rig.sniff.retries.Load()}
}

// accepted waits for the listener's side of a successful raw dial.
func (d rawRetryDial) accepted(t *testing.T) transport.Conn {
	t.Helper()
	select {
	case a := <-d.rig.acceptCh:
		if a.err != nil {
			t.Fatalf("accept: %v", a.err)
		}
		t.Cleanup(func() { a.conn.CloseWithError(0, "test done") })
		return a.conn
	case <-d.rig.ctx.Done():
		t.Fatalf("listener never accepted the connection: %v", d.rig.ctx.Err())
		return nil
	}
}

func wantSawRetry(t *testing.T, retries int64) {
	t.Helper()
	if retries < 1 {
		t.Errorf("client saw %d Retry packets, want >= 1: the handshake did not go through the source-validating listener", retries)
	}
}

func TestAgentListenTransport_NegotiatedProtocolAccessor(t *testing.T) {
	p := newPairSeam(t)
	for _, tc := range []struct {
		name, offer string
		open        bool
	}{
		{"steady branch", transport.ALPN, false},
		{"pairing branch, window open", seamPair1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := retryHandshake(t, agentListenTransport, p.listener(t, p.pairing, tc.open), p.client(t, p.srvPin, tc.offer))
			wantSawRetry(t, r.retries)
			for side, c := range map[string]transport.Conn{"listener": r.server, "client": r.client} {
				ap, ok := c.(transport.ALPNProvider)
				if !ok {
					t.Fatalf("%s Conn %T does not implement transport.ALPNProvider", side, c)
				}
				if got := ap.NegotiatedProtocol(); got != tc.offer {
					t.Errorf("%s NegotiatedProtocol() = %q, want %q", side, got, tc.offer)
				}
			}
		})
	}

	t.Run("in-memory Conn implements neither provider", func(t *testing.T) {
		hub := mem.NewHub()
		ln, err := hub.Transport("srv").Listen()
		if err != nil {
			t.Fatalf("mem listen: %v", err)
		}
		defer ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := hub.Transport("cli").Dial(ctx, "srv")
		if err != nil {
			t.Fatalf("mem dial: %v", err)
		}
		defer c.CloseWithError(0, "")
		if _, ok := c.(transport.ALPNProvider); ok {
			t.Errorf("mem Conn %T implements ALPNProvider; it has no TLS", c)
		}
		if _, ok := c.(transport.EKMProvider); ok {
			t.Errorf("mem Conn %T implements EKMProvider; it has no TLS", c)
		}
	})
}

func TestAgentListenTransport_ExporterMatchesOnBothEnds(t *testing.T) {
	p := newPairSeam(t)
	for _, tc := range []struct {
		name, offer string
		open        bool
	}{
		{"pairing branch, window open", seamPair1, true},
		{"steady branch", transport.ALPN, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := retryRawDial(t, agentListenTransport, p.listener(t, p.pairing, tc.open), p.client(t, p.srvPin, tc.offer))
			if d.err != nil {
				t.Fatalf("dial: %v", d.err)
			}
			wantSawRetry(t, d.retries)
			srv := d.accepted(t)
			select {
			case <-srv.HandshakeComplete():
			case <-d.rig.ctx.Done():
				t.Fatal("listener handshake never completed")
			}
			ekm, ok := srv.(transport.EKMProvider)
			if !ok {
				t.Fatalf("listener Conn %T does not implement transport.EKMProvider", srv)
			}
			cs := d.conn.ConnectionState().TLS
			const n = 32
			ctxA, ctxB := []byte("context-a"), []byte("context-b")

			want, err := cs.ExportKeyingMaterial(pairEKMLabel, ctxA, n)
			if err != nil {
				t.Fatalf("raw client export: %v", err)
			}
			if bytes.Equal(want, make([]byte, n)) {
				t.Fatal("raw client exported all zeros: the reference is blind")
			}
			got, err := ekm.ExportKeyingMaterial(pairEKMLabel, ctxA, n)
			if err != nil {
				t.Fatalf("listener ExportKeyingMaterial: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("listener exported %x, raw client %x: the two ends disagree", got, want)
			}
			otherCtx, err := ekm.ExportKeyingMaterial(pairEKMLabel, ctxB, n)
			if err != nil {
				t.Fatalf("listener export, other context: %v", err)
			}
			if bytes.Equal(otherCtx, got) {
				t.Errorf("another context exported the same bytes %x", got)
			}
			if ref, _ := cs.ExportKeyingMaterial(pairEKMLabel, ctxB, n); !bytes.Equal(otherCtx, ref) {
				t.Errorf("other context: listener %x, raw client %x", otherCtx, ref)
			}
			otherLabel, err := ekm.ExportKeyingMaterial("EXPERIMENTAL-quic-link-other", ctxA, n)
			if err != nil {
				t.Fatalf("listener export, other label: %v", err)
			}
			if bytes.Equal(otherLabel, got) {
				t.Errorf("another label exported the same bytes %x", got)
			}
		})
	}
}

// wantTransportErr requires a *quic.TransportError with code and side in err.
func wantTransportErr(t *testing.T, what string, err error, code quic.TransportErrorCode, remote bool) {
	t.Helper()
	var te *quic.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("%s = %v, want *quic.TransportError 0x%x", what, err, uint64(code))
	}
	if te.ErrorCode != code || te.Remote != remote {
		t.Errorf("%s = TransportError 0x%x remote=%v, want 0x%x remote=%v", what, uint64(te.ErrorCode), te.Remote, uint64(code), remote)
	}
}

// TestAgentListenTransport_PairRefusalShapes is an input-shape check: it pins
// the raw errors a joiner receives through the agent's listening socket, which
// are what the pairing dial classifier in internal/transport keys on. It
// passes from the start; the classification itself is tested there.
func TestAgentListenTransport_PairRefusalShapes(t *testing.T) {
	p := newPairSeam(t)
	refusing := p.pairing.Clone()
	refusing.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
		return errors.New("test: pairing listener refuses every joiner certificate")
	}

	t.Run("closed window: remote 0x178 at dial", func(t *testing.T) {
		d := retryRawDial(t, agentListenTransport, p.listener(t, p.pairing, false), p.client(t, p.srvPin, seamPair1))
		wantSawRetry(t, d.retries)
		wantTransportErr(t, "dial err", d.err, 0x178, true)
	})

	t.Run("joiner pinned to another key: local 0x12a at dial", func(t *testing.T) {
		d := retryRawDial(t, agentListenTransport, p.listener(t, p.pairing, true), p.client(t, p.otherPin, seamPair1))
		wantSawRetry(t, d.retries)
		wantTransportErr(t, "dial err", d.err, 0x12a, false)
	})

	t.Run("listener refuses the joiner: remote 0x12a on first read and as cause", func(t *testing.T) {
		d := retryRawDial(t, agentListenTransport, p.listener(t, refusing, true), p.client(t, p.srvPin, seamPair1))
		wantSawRetry(t, d.retries)
		if d.err != nil {
			t.Fatalf("dial: %v (under TLS 1.3 the client finishes before the listener checks its certificate)", d.err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := d.conn.AcceptStream(ctx)
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("first read timed out instead of seeing the refusal: %v", err)
		}
		wantTransportErr(t, "first read err", err, 0x12a, true)
		wantTransportErr(t, "context.Cause", context.Cause(d.conn.Context()), 0x12a, true)
	})

	t.Run("steady wrong-pin dial is still an auth failure", func(t *testing.T) {
		d := retryRawDial(t, agentListenTransport, p.listener(t, p.pairing, false), p.client(t, p.otherPin, transport.ALPN))
		wantSawRetry(t, d.retries)
		wantTransportErr(t, "dial err", d.err, 0x12a, false)
		if !transport.IsAuthFailed(d.err) {
			t.Errorf("IsAuthFailed(%v) = false, want true", d.err)
		}
	})
}
