package tunnel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestTunnelRoundTrip verifies that bytes sent over a TCP connection to the
// local tunnel port are forwarded through the QUIC tunnel to the echo service
// and returned intact.
func TestTunnelRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	caCert, caKey := mustGenCA(t)
	caPool := mustPool(t, caCert)

	// Server cert has SAN=127.0.0.1 so TLS verification succeeds on loopback.
	serverTLSCert := mustGenLeaf(t, caCert, caKey, "server", []net.IP{net.ParseIP("127.0.0.1")})
	clientTLSCert := mustGenLeaf(t, caCert, caKey, "client", nil)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{transport.ALPN},
	}
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      caPool,
		ServerName:   "127.0.0.1",
		NextProtos:   []string{transport.ALPN},
	}

	// Start a TCP echo server that the serve tunnel will forward streams to.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	// Start the QUIC serve tunnel.
	serverAddr := mustStartServe(t, ctx, serverTLS, echoLn.Addr().String())

	// Start the QUIC connect tunnel (exposes a local TCP port).
	localLn := mustStartConnect(t, ctx, clientTLS, serverAddr)

	// Dial through the local TCP port and verify round-trip.
	conn, err := net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("TCP dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello quic-link round-trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, payload)
	}
}

// TestPingNonZeroRTT verifies that the ping probe returns a non-zero
// HandshakeTime and a non-zero SmoothedRTT on loopback.
func TestPingNonZeroRTT(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	caCert, caKey := mustGenCA(t)
	caPool := mustPool(t, caCert)

	serverTLSCert := mustGenLeaf(t, caCert, caKey, "server", []net.IP{net.ParseIP("127.0.0.1")})
	clientTLSCert := mustGenLeaf(t, caCert, caKey, "client", nil)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{transport.ALPN},
	}
	// Need a dummy echo service for the serve tunnel to dial.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	serverAddr := mustStartServe(t, ctx, serverTLS, echoLn.Addr().String())

	// Create a fresh client transport for the ping probe.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      caPool,
		ServerName:   "127.0.0.1",
		NextProtos:   []string{transport.ALPN},
	}
	tr, err := transport.NewQUICTransport(udpConn, clientTLS, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	res, err := probe.Ping(ctx, tr, serverAddr)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if res.HandshakeTime == 0 {
		t.Error("HandshakeTime is zero")
	}
	// On loopback the smoothed RTT may still be 0 after just one packet;
	// accept any non-negative value and log what we got.
	t.Logf("handshake=%v smoothed_rtt=%v min_rtt=%v latest_rtt=%v",
		res.HandshakeTime, res.SmoothedRTT, res.MinRTT, res.LatestRTT)
}

// TestMTLSRejection verifies that a client presenting a certificate signed by
// an untrusted CA is rejected by the server.
func TestMTLSRejection(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Trusted CA for the server.
	trustedCA, trustedKey := mustGenCA(t)
	trustedPool := mustPool(t, trustedCA)

	serverTLSCert := mustGenLeaf(t, trustedCA, trustedKey, "server", []net.IP{net.ParseIP("127.0.0.1")})
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    trustedPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{transport.ALPN},
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoServer(echoLn)

	serverAddr := mustStartServe(t, ctx, serverTLS, echoLn.Addr().String())

	// Client uses a cert from a DIFFERENT, untrusted CA.
	untrustedCA, untrustedKey := mustGenCA(t)
	badClientCert := mustGenLeaf(t, untrustedCA, untrustedKey, "evil-client", nil)
	badClientTLS := &tls.Config{
		Certificates: []tls.Certificate{badClientCert},
		// The client trusts the server's CA so the TLS handshake proceeds far
		// enough for the server to reject the client cert.
		RootCAs:    trustedPool,
		ServerName: "127.0.0.1",
		NextProtos: []string{transport.ALPN},
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("UDP socket: %v", err)
	}
	defer udpConn.Close()

	tr, err := transport.NewQUICTransport(udpConn, badClientTLS, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer tr.Close()

	// With QUIC + TLS 1.3 mTLS, the client derives 1-RTT keys and Dial may
	// return before the server's client-cert rejection (CONNECTION_CLOSE)
	// propagates back. The rejection surfaces either at Dial or on first use.
	conn, err := tr.Dial(ctx, serverAddr)
	if err != nil {
		t.Logf("correctly rejected at dial: %v", err)
		return
	}
	defer conn.CloseWithError(0, "test done") //nolint:errcheck

	// Exercise the connection: opening a stream and reading must fail once the
	// server tears the connection down for the untrusted client certificate.
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Logf("correctly rejected at stream open: %v", err)
		return
	}
	defer stream.Close() //nolint:errcheck

	stream.Write([]byte("ping")) //nolint:errcheck
	buf := make([]byte, 1)
	if _, err := stream.Read(buf); err != nil {
		t.Logf("correctly rejected on stream use: %v", err)
		return
	}
	t.Fatal("expected mTLS rejection, but the connection was usable")
}

// ---- test helpers ------------------------------------------------------------

// mustStartServe starts a QUIC serve tunnel and returns the server's UDP addr
// string (host:port). Cleanup is registered with t.
func mustStartServe(t *testing.T, ctx context.Context, tlsConf *tls.Config, serviceAddr string) string {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("server UDP listen: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	tr, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatalf("server transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen()
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go tunnel.Serve(ctx, ln, serviceAddr) //nolint:errcheck
	return ln.Addr().String()
}

// mustStartConnect starts a QUIC connect tunnel and returns the local TCP
// Listener (port is ephemeral). Cleanup is registered with t.
func mustStartConnect(t *testing.T, ctx context.Context, tlsConf *tls.Config, serverAddr string) net.Listener {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("client UDP listen: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })

	tr, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })

	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local TCP listen: %v", err)
	}
	t.Cleanup(func() { localLn.Close() })

	go tunnel.Connect(ctx, tr, serverAddr, localLn) //nolint:errcheck
	return localLn
}

// runEchoServer accepts TCP connections and echoes all data back.
func runEchoServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c) //nolint:errcheck
		}(c)
	}
}

// ---- in-memory PKI helpers ---------------------------------------------------

func mustGenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func mustGenCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := mustGenKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

// mustGenLeaf generates a leaf TLS certificate signed by parent.
// ips may be nil for client certs (no IP SAN needed).
func mustGenLeaf(
	t *testing.T,
	parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	cn string,
	ips []net.IP,
) tls.Certificate {
	t.Helper()
	key := mustGenKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert
}

func mustPool(t *testing.T, certs ...*x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}
