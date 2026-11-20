package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mauriciomem/quic-link/internal/atomicfile"
	"github.com/pelletier/go-toml/v2"
)

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
// creating the parent directory 0700. The write is atomic and durable (see
// atomicfile.Write), so a world-readable private key never exists even
// momentarily.
func WriteKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal PKCS#8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return atomicfile.Write(path, pemBytes, 0o600)
}

// WriteMeta writes the machine-owned sidecar "<keyPath>.meta" (TOML, 0600)
// recording the key's creation time as an RFC3339 UTC string. It drives
// rotation-reminder hygiene only — never a trust decision — and is not user
// config.
func WriteMeta(keyPath string, created time.Time) error {
	content := fmt.Sprintf("created = %q\n", created.UTC().Format(time.RFC3339))
	return atomicfile.Write(keyPath+".meta", []byte(content), 0o600)
}

// ReadMeta parses the "<keyPath>.meta" sidecar written by WriteMeta and
// returns the recorded key creation time. present is false (with nil error)
// when the sidecar is absent — an unknown key age is not an error and must
// not trigger a warning. A present but malformed sidecar returns an error.
//
// The sidecar format is a single TOML key: created = "<RFC3339 UTC>".
// go-toml is used for parsing so quoting variants (single vs double quote,
// multi-line) are all handled correctly without bespoke string trimming.
func ReadMeta(keyPath string) (created time.Time, present bool, err error) {
	data, err := os.ReadFile(keyPath + ".meta")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, fmt.Errorf("read key metadata %s.meta: %w", keyPath, err)
	}
	var m struct {
		Created string `toml:"created"`
	}
	if err := toml.Unmarshal(data, &m); err != nil {
		return time.Time{}, false, fmt.Errorf("parse key metadata %s.meta: %w", keyPath, err)
	}
	if m.Created == "" {
		return time.Time{}, false, fmt.Errorf("key metadata %s.meta: missing \"created\" field", keyPath)
	}
	t, err := time.Parse(time.RFC3339, m.Created)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("key metadata %s.meta: created is not RFC3339: %w", keyPath, err)
	}
	return t, true, nil
}
