package router

import (
	"crypto/x509"
	"errors"

	"github.com/mauriciomem/quic-link/internal/identity"
)

// Identity is an authenticated peer's stable credential: base64(SHA-256(SPKI)).
// Under pinning it is the sole trust credential — the same value the peer's
// keygen printed and the agent's authorized-client pins are compared against.
// Empty Pin = unauthenticated.
type Identity struct{ Pin string }

func IdentityFromCerts(certs []*x509.Certificate) (Identity, error) {
	if len(certs) == 0 {
		return Identity{}, errors.New("router: peer presented no certificate")
	}
	// Single source of truth for the pin formula: identity.PinFromCert.
	return Identity{Pin: identity.PinFromCert(certs[0])}, nil
}

func (id Identity) Short() string {
	const n = 8
	if len(id.Pin) < n {
		return id.Pin
	}
	return id.Pin[:n]
}
