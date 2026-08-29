// Package identity is the single source of truth for quic-link's peer
// credential — the pin — and for the raw-public-key pinning TLS handshake.
//
// A pin is base64std(SHA-256(SubjectPublicKeyInfo DER)) over an Ed25519 key.
// Each endpoint holds an Ed25519 keypair wrapped in a runtime self-signed X.509
// certificate used ONLY as a TLS key carrier; verification ignores every X.509
// semantic (chain, expiry, SANs) and compares pins. Because the pin is derived
// from the SubjectPublicKeyInfo alone, the pin computed from the carrier
// certificate equals the pin keygen prints for the same key.
//
// The package is split across three files: pin.go (the pin credential and its
// parsing), key.go (Ed25519 key generation, loading, and on-disk persistence),
// and tls.go (the carrier certificate and the pinning tls.Config builders).
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Pin computes the canonical peer credential: base64std(SHA-256(spkiDER)).
// spkiDER is a DER-encoded SubjectPublicKeyInfo.
func Pin(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// PinFromCert computes the pin from a parsed certificate's public key. This is
// the one formula the whole codebase shares.
func PinFromCert(cert *x509.Certificate) string {
	return Pin(cert.RawSubjectPublicKeyInfo)
}

// PinFromPublic computes the pin from an Ed25519 public key by marshalling it to
// SubjectPublicKeyInfo DER first. For a given key this equals PinFromCert of any
// carrier certificate built over the same key (identical SPKI bytes).
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

// ParsePin validates and canonicalizes a user-supplied pin string (from a flag).
// It trims surrounding whitespace (users paste with trailing newlines),
// base64-decodes, requires exactly 32 bytes (a SHA-256 digest), and re-encodes
// so the returned pin is canonical — otherwise a non-canonical spelling of a
// valid pin would fail to match the canonical pin computed during the handshake.
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
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ErrPinNotCanonical is returned by ParsePinStrict when a pin decodes to a
// valid 32-byte digest but is not written in its own canonical spelling —
// surrounding whitespace, or a non-canonical base64 trailing-bit variant of
// the same digest, are the two ways this happens in practice. ParsePin
// repairs both; ParsePinStrict does not, because every caller of
// ParsePinStrict is handling a stored credential, and a credential that is
// not already in its expected form is refused rather than corrected.
var ErrPinNotCanonical = errors.New("pin is not canonical")

// ParsePinStrict is ParsePin's stricter sibling: it validates s exactly as
// ParsePin does, but additionally refuses any input that is not already
// byte-identical to ParsePin's own canonical return value. Every entry point
// that treats a pin as a credential to trust is held to this rule before the
// value is used — a config file's pin or authorized_clients entry (enforced
// by internal/config's validation), a --server-pin or --authorized-client
// flag (checked directly at parse time), and a verb's own --pin flag such as
// stdio's (checked directly) or ping's (checked when the effective config is
// validated, the same gate a config-file pin goes through) — so one
// definition of "canonical" governs every pin the tree accepts, rather than
// each caller re-deriving the comparison for itself.
func ParsePinStrict(s string) (string, error) {
	canonical, err := ParsePin(s)
	if err != nil {
		return "", err
	}
	if canonical != s {
		return "", ErrPinNotCanonical
	}
	return canonical, nil
}

// PinForKeyFile returns the pin of the key stored at path, expanding a leading
// ~ the way every other path in the config is. It is a convenience for callers
// that need to recognise their own identity without keeping the key itself
// around.
func PinForKeyFile(path string) (string, error) {
	key, err := LoadKey(ExpandHome(path))
	if err != nil {
		return "", err
	}
	return PinForKey(key)
}

// ExpandHome replaces a leading ~ with the user's home directory. Paths in the
// config are written the way a person would type them.
func ExpandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}
