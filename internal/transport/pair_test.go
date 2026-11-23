/**
 * @spec-handoff
 * @interface const ALPNPair = "quic-link/pair1"
 * @interface classifyPairDialError(err error) error  // unexported; reached via export_test.go
 * @behavior
 *   - nil -> nil
 *   - any *quic.TransportError 0x178 in the chain -> wraps errNoPairingWindow, message names 0x178
 *   - any *quic.TransportError 0x12a in the chain (local or remote) -> wraps errPairBlobMismatch, message names 0x12a
 *   - the two pairing classes drop the original chain: not ErrAuthFailed, not IsAuthFailed, no *quic.TransportError
 *   - anything else is returned unchanged (transient; a handshake timeout stays ErrUnreachable)
 *   - real refusals over loopback QUIC through NewQUICListenTransport (a Retry is seen first):
 *     closed window -> no-window; joiner pinned to another key -> blob mismatch from Dial;
 *     listener refusing the joiner's certificate -> blob mismatch from the first read and from context.Cause
 * @edge-cases
 *   - input already wrapped by classifyDialError (QUICTransport.Dial always wraps) or by %w still classifies
 *   - 0x150 internal_error and an application close are transient, not blob mismatch
 * @see ./quic_transport.go
 */
package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// pairALPN is the pairing ALPN spelled independently of the constant under test.
const pairALPN = "quic-link/pair1"

func TestALPNPair_IsPairingProtocol(t *testing.T) {
	if transport.ALPNPair != pairALPN {
		t.Errorf("ALPNPair = %q, want %q", transport.ALPNPair, pairALPN)
	}
	if transport.ALPNPair == transport.ALPN {
		t.Errorf("ALPNPair = ALPN = %q: pairing must negotiate a protocol distinct from v1", transport.ALPN)
	}
}

// wantPairClass checks that got is the pairing class want, that it names the
// QUIC code, and that the original chain was dropped so no auth-failure
// mapping can ever see it.
func wantPairClass(t *testing.T, got, want error, code string) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("classified = %v, want errors.Is(%v)", got, want)
	}
	if !strings.Contains(got.Error(), code) {
		t.Errorf("classified message %q does not name %s", got.Error(), code)
	}
	if errors.Is(got, transport.ErrAuthFailed) {
		t.Errorf("classified %v still matches ErrAuthFailed (would map to the auth exit code)", got)
	}
	if transport.IsAuthFailed(got) {
		t.Errorf("IsAuthFailed(%v) = true, want false", got)
	}
	var te *quic.TransportError
	if errors.As(got, &te) {
		t.Errorf("classified %v still carries *quic.TransportError 0x%x", got, uint64(te.ErrorCode))
	}
}

func TestClassifyPairDialError_Table(t *testing.T) {
	noApp := &quic.TransportError{ErrorCode: 0x178, Remote: true}
	badCertRemote := &quic.TransportError{ErrorCode: 0x12a, Remote: true}
	badCertLocal := &quic.TransportError{ErrorCode: 0x12a, Remote: false}

	if got := transport.ClassifyPairDialError(nil); got != nil {
		t.Errorf("ClassifyPairDialError(nil) = %v, want nil", got)
	}

	classes := []struct {
		name string
		in   error
		want error
		code string
	}{
		{"0x178 raw", noApp, transport.ErrNoPairingWindow, "0x178"},
		{"0x178 wrapped by classifyDialError", transport.ClassifyDialError(noApp), transport.ErrNoPairingWindow, "0x178"},
		{"0x178 wrapped twice", fmt.Errorf("dial: %w", transport.ClassifyDialError(noApp)), transport.ErrNoPairingWindow, "0x178"},
		{"0x12a remote raw", badCertRemote, transport.ErrPairBlobMismatch, "0x12a"},
		{"0x12a local raw", badCertLocal, transport.ErrPairBlobMismatch, "0x12a"},
		{"0x12a wrapped by classifyDialError", transport.ClassifyDialError(badCertLocal), transport.ErrPairBlobMismatch, "0x12a"},
		{"0x12a wrapped twice", fmt.Errorf("read: %w", transport.ClassifyDialError(badCertRemote)), transport.ErrPairBlobMismatch, "0x12a"},
	}
	for _, tc := range classes {
		t.Run(tc.name, func(t *testing.T) {
			wantPairClass(t, transport.ClassifyPairDialError(tc.in), tc.want, tc.code)
		})
	}

	timeout := transport.ClassifyDialError(&quic.HandshakeTimeoutError{})
	transient := []struct {
		name string
		in   error
	}{
		{"0x150 internal_error", &quic.TransportError{ErrorCode: 0x150, Remote: true}},
		{"0x150 wrapped by classifyDialError", transport.ClassifyDialError(&quic.TransportError{ErrorCode: 0x150, Remote: true})},
		{"application close", &quic.ApplicationError{ErrorCode: 7, Remote: true}},
		{"handshake timeout", timeout},
		{"plain error", errors.New("boom")},
	}
	for _, tc := range transient {
		t.Run("transient "+tc.name, func(t *testing.T) {
			got := transport.ClassifyPairDialError(tc.in)
			if got != tc.in {
				t.Errorf("ClassifyPairDialError(%v) = %v, want the input unchanged", tc.in, got)
			}
			if errors.Is(got, transport.ErrNoPairingWindow) || errors.Is(got, transport.ErrPairBlobMismatch) {
				t.Errorf("transient %v classified as a pairing class: %v", tc.in, got)
			}
		})
	}
	if !errors.Is(transport.ClassifyPairDialError(timeout), transport.ErrUnreachable) {
		t.Errorf("handshake timeout no longer ErrUnreachable after pair classification")
	}
}

// pairRetrySniff wraps the client socket and counts QUIC v1 Retry packets.
// It embeds the net.PacketConn interface, not *net.UDPConn, so quic-go reads
// through ReadFrom here instead of its out-of-band path.
type pairRetrySniff struct {
	net.PacketConn
	retries atomic.Int64
}

func (c *pairRetrySniff) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n >= 5 && p[0]&0xF0 == 0xF0 && binary.BigEndian.Uint32(p[1:5]) == 1 {
		c.retries.Add(1)
	}
	return n, addr, err
}

func pairUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func pairKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	k, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	p, err := identity.PinForKey(k)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	return k, p
}

// pairListen serves tlsConf on a listener built by NewQUICListenTransport (the
// constructor the agent's listening socket uses) and accepts in the
// background until cleanup.
func pairListen(t *testing.T, tlsConf *tls.Config) string {
	t.Helper()
	tr, err := transport.NewQUICListenTransport(pairUDP(t), tlsConf, nil)
	if err != nil {
		t.Fatalf("NewQUICListenTransport: %v", err)
	}
	ln, err := tr.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		var held []transport.Conn
		defer func() {
			for _, c := range held {
				c.CloseWithError(0, "")
			}
		}()
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		tr.Close()
		<-done
	})
	return ln.Addr().String()
}

// pairDial dials addr as a joiner offering only the pairing ALPN, pinned to
// serverPin, through QUICTransport.Dial (so the error is already wrapped by
// classifyDialError), and reports how many Retry packets the client saw.
func pairDial(t *testing.T, addr string, cliKey ed25519.PrivateKey, serverPin string, protos ...string) (transport.Conn, int64, error) {
	t.Helper()
	base, err := identity.ClientDialTLS(cliKey, serverPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	conf := base.Clone()
	conf.NextProtos = protos
	sniff := &pairRetrySniff{PacketConn: pairUDP(t)}
	tr, err := transport.NewQUICTransport(sniff, conf, nil)
	if err != nil {
		t.Fatalf("NewQUICTransport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr)
	if err == nil {
		t.Cleanup(func() { conn.CloseWithError(0, "") })
	}
	return conn, sniff.retries.Load(), err
}

func wantRetry(t *testing.T, retries int64) {
	t.Helper()
	if retries < 1 {
		t.Errorf("client saw %d Retry packets, want >= 1: the listener did not validate the source", retries)
	}
}

// TestClassifyPairDialError_RealRefusals classifies the errors a joiner
// actually receives from real refused handshakes. A real joiner cannot make
// the shipped pairing config refuse it (that config only requires a parsable
// leaf), so the listener-side refusal uses a pairing config built here whose
// certificate check always refuses.
func TestClassifyPairDialError_RealRefusals(t *testing.T) {
	srvKey, srvPin := pairKey(t)
	cliKey, cliPin := pairKey(t)
	_, otherPin := pairKey(t)

	steady, err := identity.AgentListenTLS(srvKey, []string{cliPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	steadySrc := func() (*tls.Config, error) { return steady, nil }
	pairing, err := identity.PairingTLS(srvKey)
	if err != nil {
		t.Fatalf("PairingTLS: %v", err)
	}
	refusing := pairing.Clone()
	refusing.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
		return errors.New("test: pairing listener refuses every joiner certificate")
	}
	serve := func(t *testing.T, pairingConf *tls.Config, open bool) string {
		t.Helper()
		outer, err := identity.ListenTLSWithPairingConfig(steadySrc, pairingConf, func() bool { return open })
		if err != nil {
			t.Fatalf("ListenTLSWithPairingConfig: %v", err)
		}
		return pairListen(t, outer)
	}

	t.Run("closed window is no-window", func(t *testing.T) {
		addr := serve(t, pairing, false)
		_, retries, err := pairDial(t, addr, cliKey, srvPin, pairALPN)
		wantRetry(t, retries)
		if err == nil {
			t.Fatal("dial with the window closed succeeded")
		}
		wantPairClass(t, transport.ClassifyPairDialError(err), transport.ErrNoPairingWindow, "0x178")
	})

	t.Run("joiner pinned to another key is blob mismatch at dial", func(t *testing.T) {
		addr := serve(t, pairing, true)
		_, retries, err := pairDial(t, addr, cliKey, otherPin, pairALPN)
		wantRetry(t, retries)
		if err == nil {
			t.Fatal("dial pinned to another key succeeded")
		}
		wantPairClass(t, transport.ClassifyPairDialError(err), transport.ErrPairBlobMismatch, "0x12a")
	})

	t.Run("listener refusing the joiner is blob mismatch on first read and cause", func(t *testing.T) {
		addr := serve(t, refusing, true)
		conn, retries, err := pairDial(t, addr, cliKey, srvPin, pairALPN)
		wantRetry(t, retries)
		if err != nil {
			t.Fatalf("dial: %v (under TLS 1.3 the client finishes before the listener checks its certificate)", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, readErr := conn.AcceptStream(ctx)
		if readErr == nil {
			t.Fatal("first read on a refused connection succeeded")
		}
		if errors.Is(readErr, context.DeadlineExceeded) {
			t.Fatalf("first read timed out instead of seeing the refusal: %v", readErr)
		}
		wantPairClass(t, transport.ClassifyPairDialError(readErr), transport.ErrPairBlobMismatch, "0x12a")
		// quic-go unblocks AcceptStream before it cancels the connection context with
		// the close cause, so wait for the context to end before reading the cause.
		select {
		case <-conn.Context().Done():
		case <-time.After(5 * time.Second):
			t.Fatal("connection context not done 5 s after the first read saw the refusal")
		}
		cause := context.Cause(conn.Context())
		if cause == nil {
			t.Fatal("connection context has no cause after the refusal")
		}
		wantPairClass(t, transport.ClassifyPairDialError(cause), transport.ErrPairBlobMismatch, "0x12a")
	})

	t.Run("steady dial still classifies as an auth failure", func(t *testing.T) {
		addr := serve(t, pairing, false)
		_, retries, err := pairDial(t, addr, cliKey, otherPin, transport.ALPN)
		wantRetry(t, retries)
		if err == nil || !errors.Is(err, transport.ErrAuthFailed) {
			t.Fatalf("steady dial err = %v, want ErrAuthFailed as today", err)
		}
	})
}
