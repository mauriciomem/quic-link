package router

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// Identity is an authenticated peer's stable credential: base64(SHA-256(SPKI)).
// Under CA-file mTLS today it is computed but not yet the trust decision; when
// pinning lands it becomes the sole credential. Empty Pin = unauthenticated.
type Identity struct{ Pin string }

func IdentityFromCerts(certs []*x509.Certificate) (Identity, error) {
	if len(certs) == 0 {
		return Identity{}, errors.New("router: peer presented no certificate")
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return Identity{Pin: base64.StdEncoding.EncodeToString(sum[:])}, nil
}

func (id Identity) Short() string {
	const n = 8
	if len(id.Pin) < n {
		return id.Pin
	}
	return id.Pin[:n]
}
