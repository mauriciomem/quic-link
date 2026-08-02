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

// transportMode selects the TLS shape, which follows who opens the connection
// rather than which logical role the endpoint plays. The two axes are
// independent: a client can listen and an agent can dial.
type transportMode int

const (
	// modeDial is for the endpoint that opens the connection. It presents its
	// certificate and skips chain verification so the pin callback is reached
	// on the peer's certificate.
	modeDial transportMode = iota
	// modeListen is for the endpoint that accepts. It presents its certificate
	// and REQUIRES one from the peer, because a listener that does not request
	// a peer certificate never runs its pin callback and so authenticates
	// nobody.
	modeListen
)

// pinningTLS is the single place the TLS knobs are set. Every constructor below
// funnels through it so the two axes cannot drift apart: mode decides the
// shape, allowed decides which identities are acceptable.
func pinningTLS(key ed25519.PrivateKey, mode transportMode, allowed []string) (*tls.Config, error) {
	if len(allowed) == 0 {
		return nil, errors.New("identity: at least one expected peer pin is required")
	}
	for _, p := range allowed {
		if p == "" {
			return nil, errors.New("identity: expected peer pin must not be empty")
		}
	}
	carrier, err := SelfSignedCarrier(key)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(allowed))
	for _, p := range allowed {
		set[p] = struct{}{}
	}

	conf := &tls.Config{
		Certificates:          []tls.Certificate{carrier},
		VerifyPeerCertificate: verifyPin(set),
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{transport.ALPN},
	}
	switch mode {
	case modeListen:
		// Request a peer certificate but skip chain verification; the pin check
		// in VerifyPeerCertificate is our stricter replacement. Without this the
		// callback is never invoked and any peer completes the handshake.
		conf.ClientAuth = tls.RequireAnyClientCert
	case modeDial:
		// Disables chain verification only, so the callback is reached and can
		// do an exact key match, which is stricter than chain verification.
		conf.InsecureSkipVerify = true //nolint:gosec // replaced by the exact-pin check in verifyPin
	}
	return conf, nil
}

// ClientDialTLS builds the config for a client that dials its agent: it
// presents its own certificate and accepts the peer only if the peer's pin
// equals the configured server pin.
func ClientDialTLS(key ed25519.PrivateKey, expectedServerPin string) (*tls.Config, error) {
	return pinningTLS(key, modeDial, []string{expectedServerPin})
}

// ClientListenTLS builds the config for a client that waits for its agent to
// connect to it. The pin set is the same single server pin a dialing client
// expects; only the shape differs, because this endpoint accepts rather than
// opens the connection and so must require a certificate from the peer.
func ClientListenTLS(key ed25519.PrivateKey, expectedServerPin string) (*tls.Config, error) {
	return pinningTLS(key, modeListen, []string{expectedServerPin})
}

// AgentListenTLS builds the config for an agent that waits for clients to
// connect: it presents its certificate, requires one from the peer, and accepts
// only pins in authorized, which must be non-empty because there is no
// unauthenticated listener.
func AgentListenTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	return pinningTLS(key, modeListen, authorized)
}

// AgentDialTLS builds the config for an agent that connects out to its client.
// It verifies the peer against the same authorized-client set it would use when
// listening: the direction of the connection changes the TLS shape, not which
// identities the agent trusts.
func AgentDialTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	return pinningTLS(key, modeDial, authorized)
}

// ServerTLS builds the agent-side listening config.
//
// Deprecated: use AgentListenTLS. The old name reads as a transport role when
// what it actually encodes is an agent that listens.
func ServerTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	return AgentListenTLS(key, authorized)
}

// ClientTLS builds the client-side dialing config.
//
// Deprecated: use ClientDialTLS. The old name hides that the shape follows the
// transport direction, not the logical role.
func ClientTLS(key ed25519.PrivateKey, expectedServerPin string) (*tls.Config, error) {
	return ClientDialTLS(key, expectedServerPin)
}

// verifyPin returns a tls.Config.VerifyPeerCertificate callback that parses the
// peer's leaf, computes its pin, and requires membership in allowed. Returning
// an error aborts the handshake with a TLS alert.
//
// The error message includes only the first 8 characters of the peer pin (the
// same prefix used in every other log and audit site). This is sufficient for
// an operator to identify the peer's identity ("is this my client?") without
// embedding the full 44-character pin in an error string that may propagate
// through error-wrapping chains to log sinks.
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
			prefix := pin
			if len(prefix) > 8 {
				prefix = prefix[:8]
			}
			return fmt.Errorf("%w: peer pin %s…", ErrPinMismatch, prefix)
		}
		return nil
	}
}
