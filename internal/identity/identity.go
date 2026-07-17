// Package identity is the single source of truth for quic-link's peer
// credential — the pin — and for the raw-public-key pinning TLS handshake that
// replaced the Phase-0 CA-file mTLS (ADR-0004, 02 §2.2).
//
// A pin is base64std(SHA-256(SubjectPublicKeyInfo DER)) over an Ed25519 key.
// Each endpoint holds an Ed25519 keypair wrapped in a runtime self-signed X.509
// certificate used ONLY as a TLS key carrier; verification ignores every X.509
// semantic (chain, expiry, SANs) and compares pins. Because the pin is derived
// from the SPKI alone, the pin computed from the carrier cert equals the pin
// keygen prints for the same key — carrier-cert pin == public-key pin == keygen
// pin (guaranteed byte-for-byte; see identity_test.go).
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// ErrPinMismatch is returned by the pinning VerifyPeerCertificate callback when
// the peer's pin is not in the expected/authorized set. It aborts the TLS
// handshake; the dialing side classifies the resulting failure as an auth error
// (transport.ErrAuthFailed) and the process exits 4 (06 §Global).
var ErrPinMismatch = errors.New("identity: peer pin not authorized")

// ErrNoPeerCert is returned when the peer presented no certificate. There is no
// anonymous/open mode (INV-3): a callback invoked with an empty chain rejects.
var ErrNoPeerCert = errors.New("identity: peer presented no certificate")

// Pin computes the canonical peer credential: base64std(SHA-256(spkiDER))
// (02 §2.2). spkiDER is a DER-encoded SubjectPublicKeyInfo.
func Pin(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// PinFromCert computes the pin from a parsed certificate's SPKI. This is the
// one formula the whole codebase shares (router.IdentityFromCerts routes
// through it, INV: single source of truth).
func PinFromCert(cert *x509.Certificate) string {
	return Pin(cert.RawSubjectPublicKeyInfo)
}

// PinFromPublic computes the pin from an Ed25519 public key by marshalling it to
// SPKI DER first. For a given key this equals PinFromCert of any carrier cert
// built over the same key (identical SPKI bytes).
func PinFromPublic(pub ed25519.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return Pin(spki), nil
}

// PinForKey is a convenience wrapper computing the pin of a private key's public
// half — the value keygen prints.
func PinForKey(key ed25519.PrivateKey) (string, error) {
	return PinFromPublic(key.Public().(ed25519.PublicKey))
}

// ParsePin validates a user-supplied pin string (from a flag). It trims
// surrounding whitespace (users paste with trailing newlines), base64-decodes,
// and requires exactly 32 bytes (a SHA-256 digest). It returns the normalized
// pin string or an error naming the problem.
func ParsePin(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("pin is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("pin must be base64 of a 32-byte SHA-256: %w", err)
	}
	if len(raw) != sha256.Size {
		return "", fmt.Errorf("pin must be base64 of a 32-byte SHA-256: decoded %d bytes, want %d", len(raw), sha256.Size)
	}
	return s, nil
}

// Generate creates a fresh Ed25519 identity key.
func Generate() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return priv, nil
}

// LoadKey reads a PKCS#8 PEM Ed25519 private key from path.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key in %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not an Ed25519 key (got %T)", path, parsed)
	}
	return key, nil
}

// WriteKey writes key as a PKCS#8 PEM file at path with 0600 permissions,
// creating the parent directory 0700. The write is atomic (temp file in the
// same dir, chmod, rename) so a world-readable private key never exists even
// momentarily (INV-2, INV-8).
func WriteKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal PKCS#8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return writeFileAtomic(path, pemBytes, 0o600)
}

// WriteMeta writes the machine-owned sidecar "<keyPath>.meta" (TOML, 0600)
// recording the key's creation time as an RFC3339 UTC string. This drives
// rotation-reminder hygiene only — never a trust decision (ADR-0004 "Key age",
// 05 §2). It is not user config.
func WriteMeta(keyPath string, created time.Time) error {
	content := fmt.Sprintf("created = %q\n", created.UTC().Format(time.RFC3339))
	return writeFileAtomic(keyPath+".meta", []byte(content), 0o600)
}

// SelfSignedCarrier builds an ephemeral self-signed certificate over key, used
// ONLY as a TLS key carrier (02 §2.2) — nothing ever checks its validity, so the
// template is minimal and the validity window is wide (now-1h .. +100y) purely
// so no TLS stack rejects it before our pin check runs. Critically, the carrier
// cert's SPKI is byte-identical to x509.MarshalPKIXPublicKey(key.Public()), so
// its pin equals the keygen pin.
func SelfSignedCarrier(key ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("carrier serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "quic-link"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// x509.CreateCertificate auto-selects PureEd25519 for an Ed25519 key.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create carrier cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse carrier cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// ServerTLS builds the agent-side pinning tls.Config: it presents key's carrier
// cert, requires the client to present a cert (RequireAnyClientCert — NOT
// RequireAndVerifyClientCert, because we do our OWN verification), and accepts
// the peer only if its pin is in authorized. authorized must be non-empty
// (INV-3: no unauthenticated listener).
func ServerTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	if len(authorized) == 0 {
		return nil, errors.New("identity: server requires at least one authorized client pin (INV-3)")
	}
	carrier, err := SelfSignedCarrier(key)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(authorized))
	for _, p := range authorized {
		allowed[p] = struct{}{}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{carrier},
		// Request a client cert but skip chain verification; the pin check in
		// VerifyPeerCertificate is our (stricter) replacement (02 §2.2).
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPin(allowed),
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{transport.ALPN},
	}, nil
}

// ClientTLS builds the client-side pinning tls.Config: it presents key's carrier
// cert and accepts the server only if its pin equals expectedServerPin.
// InsecureSkipVerify is REQUIRED so the callback is reached — it disables X.509
// CHAIN verification, which we replace with an exact-key match (stricter, not
// weaker; 02 §2.2).
func ClientTLS(key ed25519.PrivateKey, expectedServerPin string) (*tls.Config, error) {
	if expectedServerPin == "" {
		return nil, errors.New("identity: client requires an expected server pin")
	}
	carrier, err := SelfSignedCarrier(key)
	if err != nil {
		return nil, err
	}
	allowed := map[string]struct{}{expectedServerPin: {}}
	return &tls.Config{
		Certificates: []tls.Certificate{carrier},
		// Disables chain verification only; VerifyPeerCertificate below does an
		// exact pin match — stricter than chain verification (02 §2.2).
		InsecureSkipVerify:    true, //nolint:gosec // replaced by the exact-pin check in verifyPin
		VerifyPeerCertificate: verifyPin(allowed),
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{transport.ALPN},
	}, nil
}

// verifyPin returns a tls.Config.VerifyPeerCertificate callback that parses the
// peer's leaf, computes its pin, and requires membership in allowed. Returning
// an error aborts the handshake with a TLS alert.
func verifyPin(allowed map[string]struct{}) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoPeerCert
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("identity: parse peer certificate: %w", err)
		}
		pin := PinFromCert(cert)
		if _, ok := allowed[pin]; !ok {
			return fmt.Errorf("%w: peer pin %s", ErrPinMismatch, pin)
		}
		return nil
	}
}

// writeFileAtomic writes data to path with mode, creating the parent directory
// 0700. It writes to a temp file in the same directory, chmods it, then renames
// — so readers never see a partial or default-mode file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return nil
}
