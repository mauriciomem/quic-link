package pairing

import (
	"crypto/hmac"
	"crypto/sha256"
)

const (
	// EKMLabel is the TLS exporter label for pairing proofs. It stays in the
	// EXPERIMENTAL- namespace until a label is registered.
	EKMLabel = "EXPERIMENTAL-quic-link-pairing-v1"
	// EKMLength is the number of exporter bytes the proof is computed over.
	EKMLength = 32
	// ProofLength is the size of an HMAC-SHA256 proof.
	ProofLength = sha256.Size
)

// ExporterContext returns the exporter context for label, verbatim. It is
// never nil, though under TLS 1.3 an absent and an empty context are the
// same (RFC 8446 §7.5).
func ExporterContext(label string) []byte {
	return append([]byte{}, label...)
}

// Proof returns HMAC-SHA256(key=secret, msg=ekm).
func Proof(secret, ekm []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(ekm)
	return m.Sum(nil)
}

// VerifyProof reports whether got is the proof for secret and ekm, comparing
// in constant time. A proof of the wrong length is rejected by hmac.Equal.
func VerifyProof(secret, ekm, got []byte) bool {
	return hmac.Equal(Proof(secret, ekm), got)
}
