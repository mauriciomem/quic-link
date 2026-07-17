package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// ErrPinMismatch is returned by the pinning VerifyPeerCertificate callback when
// the peer's pin is not in the expected/authorized set. It aborts the TLS
// handshake; the dialing side classifies the resulting failure as an
// authentication error and the process exits with the auth failure code.
var ErrPinMismatch = errors.New("identity: peer pin not authorized")

// ErrNoPeerCert is returned when the peer presented no certificate. There is no
// anonymous/open mode: a callback invoked with an empty chain rejects.
var ErrNoPeerCert = errors.New("identity: peer presented no certificate")

// SelfSignedCarrier builds an ephemeral self-signed certificate over key, used
// ONLY as a TLS key carrier — nothing ever checks its validity, so the template
// is minimal and the validity window is wide (now-1h .. +100y) purely so no TLS
// stack rejects it before our pin check runs. Critically, the carrier
// certificate's SubjectPublicKeyInfo is byte-identical to
// x509.MarshalPKIXPublicKey(key.Public()), so its pin equals the keygen pin.
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
// certificate, requires the client to present a certificate (RequireAnyClientCert
// — NOT RequireAndVerifyClientCert, because we do our OWN verification), and
// accepts the peer only if its pin is in authorized. authorized must be
// non-empty: there is no unauthenticated listener.
func ServerTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	if len(authorized) == 0 {
		return nil, errors.New("identity: server requires at least one authorized client pin")
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
		// VerifyPeerCertificate is our (stricter) replacement.
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyPin(allowed),
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{transport.ALPN},
	}, nil
}

// ClientTLS builds the client-side pinning tls.Config: it presents key's carrier
// certificate and accepts the server only if its pin equals expectedServerPin.
// InsecureSkipVerify is REQUIRED so the callback is reached — it disables X.509
// CHAIN verification, which we replace with an exact-key match (stricter, not
// weaker).
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
		// exact pin match — stricter than chain verification.
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
