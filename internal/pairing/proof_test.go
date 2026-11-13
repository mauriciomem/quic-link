/**
 * @spec-handoff
 * @interface Proof(secret, ekm []byte) []byte; VerifyProof(secret, ekm, got []byte) bool; ExporterContext(label string) []byte
 * @behavior
 *   - EKMLabel == "EXPERIMENTAL-quic-link-pairing-v1", EKMLength == 32, ProofLength == 32
 *   - Proof = HMAC-SHA256(key=secret, msg=ekm)
 *   - VerifyProof compares only via hmac.Equal(Proof(secret, ekm), got)
 *   - ExporterContext(label) = []byte(label); "" -> non-nil, len 0
 * @edge-cases
 *   - Wrong secret / wrong ekm / short / long / nil proof -> false
 *   - TLS 1.3 exporter: absent context == empty context (RFC 8446/9846 §7.5)
 * @see RFC 001 pairing-wire-protocol.md §4
 */

package pairing_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/pairing"
)

func TestEKMLabel_Pinned(t *testing.T) {
	if pairing.EKMLabel != "EXPERIMENTAL-quic-link-pairing-v1" {
		t.Fatalf("EKMLabel = %q", pairing.EKMLabel)
	}
	if pairing.EKMLength != 32 || pairing.ProofLength != 32 {
		t.Fatalf("EKMLength = %d, ProofLength = %d", pairing.EKMLength, pairing.ProofLength)
	}
}

func TestProof_HMACSHA256Vectors(t *testing.T) {
	// RFC 4231 test case 2.
	got := pairing.Proof([]byte("Jefe"), []byte("what do ya want for nothing?"))
	want, _ := hex.DecodeString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	if !bytes.Equal(got, want) {
		t.Fatalf("vector: got %x want %x", got, want)
	}
	secret := bytes.Repeat([]byte{0x11}, 16)
	ekm := bytes.Repeat([]byte{0x22}, 32)
	m := hmac.New(sha256.New, secret)
	m.Write(ekm)
	if !bytes.Equal(pairing.Proof(secret, ekm), m.Sum(nil)) {
		t.Fatal("Proof disagrees with crypto/hmac")
	}
}

func TestVerifyProof(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 16)
	ekm := bytes.Repeat([]byte{0x22}, 32)
	p := pairing.Proof(secret, ekm)
	if !pairing.VerifyProof(secret, ekm, p) {
		t.Fatal("valid proof rejected")
	}
	otherSecret := bytes.Repeat([]byte{0x12}, 16)
	otherEKM := bytes.Repeat([]byte{0x23}, 32)
	cases := map[string]bool{
		"wrong secret": pairing.VerifyProof(otherSecret, ekm, p),
		"wrong ekm":    pairing.VerifyProof(secret, otherEKM, p),
		"short":        pairing.VerifyProof(secret, ekm, p[:31]),
		"long":         pairing.VerifyProof(secret, ekm, append(append([]byte{}, p...), 0)),
		"nil":          pairing.VerifyProof(secret, ekm, nil),
		"flipped bit":  pairing.VerifyProof(secret, ekm, append(append([]byte{}, p[:31]...), p[31]^1)),
	}
	for name, ok := range cases {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExporterContext_AbsentEqualsEmpty(t *testing.T) {
	empty := pairing.ExporterContext("")
	if empty == nil || len(empty) != 0 {
		t.Fatalf("ExporterContext(\"\") = %#v, want non-nil empty", empty)
	}
	if !bytes.Equal(pairing.ExporterContext("laptop"), []byte("laptop")) {
		t.Fatal("label bytes not used verbatim")
	}

	cs := loopbackTLS13(t)
	absent, err := cs.ExportKeyingMaterial(pairing.EKMLabel, nil, pairing.EKMLength)
	if err != nil {
		t.Fatal(err)
	}
	withEmpty, err := cs.ExportKeyingMaterial(pairing.EKMLabel, empty, pairing.EKMLength)
	if err != nil {
		t.Fatal(err)
	}
	withLabel, err := cs.ExportKeyingMaterial(pairing.EKMLabel, pairing.ExporterContext("laptop"), pairing.EKMLength)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(absent, withEmpty) {
		t.Fatal("absent and empty context differ")
	}
	if bytes.Equal(absent, withLabel) {
		t.Fatal("label does not change the exporter output")
	}
}

// loopbackTLS13 completes an in-process TLS 1.3 handshake over net.Pipe and
// returns the client's ConnectionState. All goroutines finish before return.
func loopbackTLS13(t *testing.T) tls.ConnectionState {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}
	cliCfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srvErr := make(chan error, 1)
	srv := tls.Server(b, srvCfg)
	go func() { srvErr <- srv.HandshakeContext(ctx) }()
	cli := tls.Client(a, cliCfg)
	if err := cli.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
	return cli.ConnectionState()
}
