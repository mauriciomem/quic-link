// Package transport_test contains black-box tests for the transport package.
// This file specifically tests classifyDialError's handling of idle-timeout
// errors that arise on platforms (e.g. macOS loopback) where dialing a closed
// UDP port never produces an ICMP port-unreachable and quic-go instead exhausts
// the HandshakeIdleTimeout.
package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
	quic "github.com/quic-go/quic-go"
)

// throwawayTLSConfig builds a minimal client tls.Config using an ephemeral
// ECDSA key and self-signed certificate. The handshake never completes in this
// test, so the cert contents and the server pin are irrelevant; we only need a
// valid config so quic-go can attempt the dial.
func throwawayTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate throwaway key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "quic-link-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create throwaway cert: %v", err)
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		InsecureSkipVerify: true, //nolint:gosec // intentional: pin check omitted; handshake never completes in this test
		NextProtos:         []string{transport.ALPN},
		MinVersion:         tls.VersionTLS13,
	}
}

// closedUDPPort returns a UDP port number on 127.0.0.1 that is guaranteed to
// be unbound at the moment of the call. It works by binding a UDP socket,
// recording the assigned port, and closing the socket — leaving the port free
// but unused. The port may theoretically be re-used between the close and the
// dial, but on loopback this window is negligible and far preferable to a
// hardcoded "high" port that might actually be in use.
func closedUDPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe bind: %v", err)
	}
	addr := ln.LocalAddr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}
	return addr
}

// TestDialIdleTimeout_ClassifiedAsUnreachable proves that when quic-go
// exhausts the HandshakeIdleTimeout (because nothing is listening on the UDP
// port and no ICMP port-unreachable arrives), classifyDialError wraps the
// resulting error in ErrUnreachable rather than letting it fall through as an
// opaque error that maps to exit 1.
//
// The test uses a short HandshakeIdleTimeout (500 ms) so it completes quickly
// instead of waiting for the production 5s timeout.
func TestDialIdleTimeout_ClassifiedAsUnreachable(t *testing.T) {
	// Not marked t.Parallel() — opens a real UDP socket; keep sequential to
	// avoid port-number collisions in the port-probe helper.
	target := closedUDPPort(t)

	clientUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind client UDP socket: %v", err)
	}
	udpConn := clientUDP.(*net.UDPConn)

	quicConf := &quic.Config{
		// Short timeout so the test finishes in ~½s instead of 5s.
		HandshakeIdleTimeout: 500 * time.Millisecond,
	}

	tr, err := transport.NewQUICTransport(udpConn, throwawayTLSConfig(t), quicConf)
	if err != nil {
		t.Fatalf("NewQUICTransport: %v", err)
	}
	defer tr.Close() //nolint:errcheck

	ctx := context.Background()
	_, dialErr := tr.Dial(ctx, target)
	if dialErr == nil {
		t.Fatal("expected Dial to fail against a closed port, but it succeeded")
	}

	if !errors.Is(dialErr, transport.ErrUnreachable) {
		t.Fatalf("expected errors.Is(err, ErrUnreachable)=true; got: %v", dialErr)
	}
}
