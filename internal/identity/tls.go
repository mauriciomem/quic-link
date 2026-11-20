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
	"slices"
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

var (
	errEmptyPinSet = errors.New("identity: at least one expected peer pin is required")
	errEmptyPin    = errors.New("identity: expected peer pin must not be empty")
	errNilSource   = errors.New("identity: allowed-pin source is required")
	errResumedConn = errors.New("identity: resumed connection refused: a resumed handshake skips the peer pin check")
)

// AllowedSource returns the set of authorized peer pins. It is called once per
// handshake, from handshake goroutines, concurrently. The returned map is
// treated as read-only and must not be mutated after return. A nil or empty
// map rejects every peer; it never means "allow all".
type AllowedSource func() map[string]struct{}

// pinningTLS builds a pinning config over a fixed pin list. It only turns the
// list into a static source; every config is built by pinningTLSFrom, so the
// knobs are set in one place for list and live sources alike.
func pinningTLS(key ed25519.PrivateKey, mode transportMode, allowed []string, allowEmptyAtStart bool) (*tls.Config, error) {
	set := make(map[string]struct{}, len(allowed))
	for _, p := range allowed {
		set[p] = struct{}{}
	}
	return pinningTLSFrom(key, mode, staticSource(set), allowEmptyAtStart)
}

// staticSource is an AllowedSource that always returns set.
func staticSource(set map[string]struct{}) AllowedSource {
	return func() map[string]struct{} { return set }
}

// pinningTLSFrom is the single place the TLS knobs are set. Every constructor
// below funnels through it so the two axes cannot drift apart: mode decides
// the shape, src decides which identities are acceptable. src is called once
// here to refuse a source that authorizes nobody (or holds an empty pin), and
// then once per handshake by the pin callback, so a change to the set is seen
// by the next handshake.
//
// allowEmptyAtStart lets a listener start with no authorized pin (every peer
// is then rejected with ErrPinMismatch). Only ListenTLSWithPairing passes
// true, because a fresh agent pairs its first client through that listener.
// Every other constructor passes false, so they refuse an empty set.
func pinningTLSFrom(key ed25519.PrivateKey, mode transportMode, src AllowedSource, allowEmptyAtStart bool) (*tls.Config, error) {
	if src == nil {
		return nil, errNilSource
	}
	set, err := readSource(src)
	if err != nil {
		return nil, err
	}
	if len(set) == 0 && !allowEmptyAtStart {
		return nil, errEmptyPinSet
	}
	if _, ok := set[""]; ok {
		return nil, errEmptyPin
	}
	carrier, err := SelfSignedCarrier(key)
	if err != nil {
		return nil, err
	}

	conf := &tls.Config{
		Certificates:          []tls.Certificate{carrier},
		VerifyPeerCertificate: verifyPinFrom(src),
		VerifyConnection:      rejectResumed,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{transport.ALPN},
	}
	// Resumed handshakes skip VerifyPeerCertificate, so a session ticket
	// would bypass the only check that authenticates a peer here. Set
	// unconditionally, not per mode: both modes need the same value, unlike
	// ClientAuth/InsecureSkipVerify below, which genuinely differ by mode.
	// rejectResumed above is the second layer if tickets are ever re-enabled.
	conf.SessionTicketsDisabled = true
	switch mode {
	case modeListen:
		// Request a peer certificate but skip chain verification; the pin check
		// in VerifyPeerCertificate is our stricter replacement. Without this the
		// callback is never invoked and any peer completes the handshake.
		conf.ClientAuth = tls.RequireAnyClientCert
	case modeDial:
		// Disables chain verification only, so the callback is reached and can
		// do an exact key match, which is stricter than chain verification.
		conf.InsecureSkipVerify = true //nolint:gosec // replaced by the exact-pin check in verifyPinFrom
	}
	return conf, nil
}

// rejectResumed is the VerifyConnection callback of every pinning and pairing
// config. VerifyConnection runs on resumed connections too, unlike
// VerifyPeerCertificate, so it refuses any resumption that slips past the
// disabled session tickets.
func rejectResumed(cs tls.ConnectionState) error {
	if cs.DidResume {
		return errResumedConn
	}
	return nil
}

// readSource calls src, turning a panic into an error so a failing source
// rejects the peer instead of crashing the handshake goroutine.
func readSource(src AllowedSource) (set map[string]struct{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			set, err = nil, fmt.Errorf("identity: allowed-pin source failed: %v", r)
		}
	}()
	return src(), nil
}

// ClientDialTLS builds the config for a client that dials its agent: it
// presents its own certificate and accepts the peer only if the peer's pin
// equals the configured server pin.
func ClientDialTLS(key ed25519.PrivateKey, expectedServerPin string) (*tls.Config, error) {
	return pinningTLS(key, modeDial, []string{expectedServerPin}, false)
}

// ClientListenTLS builds the config for a client that waits for its agents to
// connect to it. It accepts a peer whose pin is any of expectedServerPins; with
// one pin it is the same check a dialing client makes, and only the shape
// differs, because this endpoint accepts rather than opens the connection and
// so must require a certificate from the peer. No pins is an empty set and is
// refused like every other empty set. That the listed pins are distinct is
// enforced by config validation, not here.
func ClientListenTLS(key ed25519.PrivateKey, expectedServerPins ...string) (*tls.Config, error) {
	return pinningTLS(key, modeListen, expectedServerPins, false)
}

// AgentListenTLS builds the config for an agent that waits for clients to
// connect: it presents its certificate, requires one from the peer, and accepts
// only pins in authorized, which must be non-empty because there is no
// unauthenticated listener.
func AgentListenTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	return pinningTLS(key, modeListen, authorized, false)
}

// AgentDialTLS builds the config for an agent that connects out to its client.
// It verifies the peer against the same authorized-client set it would use when
// listening: the direction of the connection changes the TLS shape, not which
// identities the agent trusts.
func AgentDialTLS(key ed25519.PrivateKey, authorized []string) (*tls.Config, error) {
	return pinningTLS(key, modeDial, authorized, false)
}

// AgentListenTLSFrom is AgentListenTLS reading the authorized set from src on
// every handshake. src must authorize at least one pin when called here; a
// source that later returns a nil or empty set rejects every peer.
func AgentListenTLSFrom(key ed25519.PrivateKey, src AllowedSource) (*tls.Config, error) {
	return pinningTLSFrom(key, modeListen, src, false)
}

// AgentDialTLSFrom is AgentDialTLS reading the authorized set from src on
// every handshake, with the same build-time and handshake-time rules as
// AgentListenTLSFrom.
func AgentDialTLSFrom(key ed25519.PrivateKey, src AllowedSource) (*tls.Config, error) {
	return pinningTLSFrom(key, modeDial, src, false)
}

// verifyPin is verifyPinFrom over a fixed set.
func verifyPin(allowed map[string]struct{}) func([][]byte, [][]*x509.Certificate) error {
	return verifyPinFrom(staticSource(allowed))
}

// verifyPinFrom returns a tls.Config.VerifyPeerCertificate callback that parses
// the peer's leaf, computes its pin, and requires membership in the set src
// returns for this handshake. A nil or empty set, or a panicking source,
// rejects the peer. Returning an error aborts the handshake with a TLS alert.
//
// The error message includes only the first 8 characters of the peer pin (the
// same prefix used in every other log and audit site). This is sufficient for
// an operator to identify the peer's identity ("is this my client?") without
// embedding the full 44-character pin in an error string that may propagate
// through error-wrapping chains to log sinks.
func verifyPinFrom(src AllowedSource) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoPeerCert
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("identity: parse peer certificate: %w", err)
		}
		allowed, err := readSource(src)
		if err != nil {
			return err
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

// alpnPair1 is the ALPN a pairing joiner offers. Unexported until the pairing
// transport defines its own constant.
const alpnPair1 = "quic-link/pair1"

// configSource yields the steady-state listener config for one handshake. It
// never sees the ClientHello: selection depends only on the offered ALPN list
// and the pairing-window predicate.
type configSource func() (*tls.Config, error)

var (
	errSeamNoHello   = errors.New("identity: no ClientHello")
	errSeamNilConfig = errors.New("identity: config source returned no config")
	errSeamBadSteady = errors.New("identity: steady config is not a pinning listener config")
	errSeamPanic     = errors.New("identity: listener config selection panicked")
)

// pairingDispatcher returns a tls.Config.GetConfigForClient callback that
// selects the pairing config only when the peer offers quic-link/pair1 and
// the window is open; everything else gets the steady config, so a closed
// window fails at ALPN like a version mismatch.
//
// It is total: every return is (config, nil) or (nil, error), never
// (nil, nil), and panics become errSeamPanic. A callback error makes the
// stdlib abort the handshake with an internal_error alert, which the
// transport classifier counts as an authentication failure (it treats every
// TLS alert except no_application_protocol that way).
// Every returned config is a fresh detached clone with session tickets
// disabled, because resumption would skip the pin check.
//
// The pairing config is snapshotted first and the snapshot is validated; if
// it is not an authenticating pairing config, every handshake fails with
// errSeamBadPairing (fail closed), whatever the peer offers.
func pairingDispatcher(steady configSource, pairing *tls.Config, pairingOpen func() bool) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	var snap *tls.Config
	err := errors.New("no pairing config")
	if pairing != nil {
		snap = detachedClone(pairing, pairing.NextProtos...)
		err = checkPairing(snap)
	}
	if err != nil {
		bad := fmt.Errorf("%w: %w", errSeamBadPairing, err)
		return func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, bad }
	}
	return func(hello *tls.ClientHelloInfo) (cfg *tls.Config, err error) {
		defer func() {
			if r := recover(); r != nil {
				cfg, err = nil, fmt.Errorf("%w: %v", errSeamPanic, r)
			}
		}()
		if hello == nil {
			return nil, errSeamNoHello
		}
		if slices.Contains(hello.SupportedProtos, alpnPair1) && pairingOpen() {
			return detachedClone(snap, alpnPair1), nil
		}
		c, err := steady()
		if err != nil {
			return nil, fmt.Errorf("identity: steady listener config: %w", err)
		}
		if c == nil {
			return nil, errSeamNilConfig
		}
		// Clone first and validate the clone, so the source cannot change
		// the config between the check and its use.
		out := detachedClone(c, c.NextProtos...)
		if err := checkSteady(out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// detachedClone copies c with tickets off, the given ALPN list in a fresh
// slice, and a fresh certificate list whose DER chains are copied too, so
// neither the caller's ALPN slice nor its certificate chains share memory with
// the result. Callbacks are kept so the clone can be validated; both callers
// only return clones that passed checkAuthenticating.
//
// tls.Config.Clone is shallow, so some state is still shared with c: each
// certificate's Leaf, OCSPStaple and SignedCertificateTimestamps, the private
// keys (immutable signers), CurvePreferences, the RootCAs/ClientCAs pools
// (unused: peers are checked by pin under RequireAnyClientCert or
// InsecureSkipVerify), the VerifyPeerCertificate/VerifyConnection closures (by
// design: they carry the live pin source), and Rand/Time. None of it decides
// which peer is admitted beyond the closures, which are the checks themselves.
func detachedClone(c *tls.Config, protos ...string) *tls.Config {
	out := c.Clone()
	out.SessionTicketsDisabled = true
	out.NextProtos = slices.Clone(protos)
	out.Certificates = make([]tls.Certificate, len(c.Certificates))
	for i, crt := range c.Certificates {
		chain := make([][]byte, len(crt.Certificate))
		for j, der := range crt.Certificate {
			chain[j] = slices.Clone(der)
		}
		crt.Certificate = chain
		out.Certificates[i] = crt
	}
	return out
}

// checkSteady requires an authenticating pinning listener advertising only
// the steady ALPN.
func checkSteady(c *tls.Config) error {
	if !slices.Equal(c.NextProtos, []string{transport.ALPN}) {
		return fmt.Errorf("%w: NextProtos %q", errSeamBadSteady, c.NextProtos)
	}
	if err := checkAuthenticating(c); err != nil {
		return fmt.Errorf("%w: %w", errSeamBadSteady, err)
	}
	return nil
}

// checkAuthenticating holds the shape shared by steady and pairing configs:
// TLS 1.3 only, a peer certificate is required and pin-checked, exactly one
// static carrier is presented, and no callback can swap the config or the
// certificate out.
func checkAuthenticating(c *tls.Config) error {
	switch {
	case c.MinVersion < tls.VersionTLS13:
		return errors.New("MinVersion below TLS 1.3")
	case c.ClientAuth != tls.RequireAnyClientCert:
		return errors.New("peer certificate not required")
	case c.VerifyPeerCertificate == nil:
		return errors.New("no pin callback")
	case len(c.Certificates) != 1:
		return fmt.Errorf("%d certificates, want 1", len(c.Certificates))
	case c.GetCertificate != nil:
		return errors.New("GetCertificate set")
	case c.GetConfigForClient != nil:
		return errors.New("nested GetConfigForClient")
	case c.KeyLogWriter != nil:
		return errors.New("KeyLogWriter set")
	}
	return nil
}

// checkPairing requires an authenticating config advertising exactly the
// pairing ALPN.
func checkPairing(c *tls.Config) error {
	if !slices.Equal(c.NextProtos, []string{alpnPair1}) {
		return fmt.Errorf("pairing config must advertise exactly %q, got %q", alpnPair1, c.NextProtos)
	}
	if err := checkAuthenticating(c); err != nil {
		return fmt.Errorf("pairing config: %w", err)
	}
	return nil
}

// ListenTLSWithPairingConfig builds a listener config that serves pairing
// (quic-link/pair1) while pairingOpen reports true and the steady config
// otherwise. It takes already-built configs and validates the pairing one at
// build time. The pairing config is snapshotted first as a detached copy (ALPN
// list and certificate chains included) and the snapshot is what is
// validated and served, so later caller mutation has no effect; the steady
// config is copied and checked on every handshake. The outer config carries
// no certificate, so it can never authenticate a handshake itself.
//
// Not wired into any production listener; a source-scan test guards that.
func ListenTLSWithPairingConfig(steady func() (*tls.Config, error), pairing *tls.Config, pairingOpen func() bool) (*tls.Config, error) {
	if steady == nil || pairing == nil || pairingOpen == nil {
		return nil, errors.New("identity: pairing listener needs a steady source, a pairing config and a window predicate")
	}
	snap := detachedClone(pairing, pairing.NextProtos...)
	if err := checkPairing(snap); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return &tls.Config{
		GetConfigForClient:     pairingDispatcher(steady, snap, pairingOpen),
		NextProtos:             []string{transport.ALPN},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}, nil
}

// listenRoute is the post-accept handling selected for a connection.
type listenRoute int

const (
	routeReject listenRoute = iota
	routeSteady
	routePairing
)

// routeFor selects post-accept handling from the negotiated ALPN only.
func routeFor(cs tls.ConnectionState) listenRoute {
	switch cs.NegotiatedProtocol {
	case transport.ALPN:
		return routeSteady
	case alpnPair1:
		return routePairing
	default:
		return routeReject
	}
}

// errSeamBadPairing is returned by a dispatcher whose pairing config failed
// validation, for every handshake.
var errSeamBadPairing = errors.New("identity: pairing config is not an authenticating pairing config")

// PairingTLS builds the config served to a joiner while a pairing window is
// open: TLS 1.3, ALPN exactly quic-link/pair1, a peer certificate required, no
// session tickets, resumed connections refused, and a certificate check that
// only requires the leaf to parse. The joiner's pin is read after the
// handshake from the connection, never here: VerifyPeerCertificate runs before
// the peer has proved possession of the key.
func PairingTLS(key ed25519.PrivateKey) (*tls.Config, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("identity: pairing config needs an Ed25519 private key")
	}
	carrier, err := SelfSignedCarrier(key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:           []tls.Certificate{carrier},
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{alpnPair1},
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifyParsableLeaf,
		VerifyConnection:       rejectResumed,
	}, nil
}

// verifyParsableLeaf admits any peer presenting a certificate whose leaf
// parses; the pairing protocol, not TLS, decides whether the joiner is
// admitted.
func verifyParsableLeaf(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return ErrNoPeerCert
	}
	if _, err := x509.ParseCertificate(rawCerts[0]); err != nil {
		return fmt.Errorf("identity: parse peer certificate: %w", err)
	}
	return nil
}

// ListenTLSWithPairing builds the agent listener config that serves pairing
// while pairingOpen reports true and the steady pinning listener otherwise.
// The steady branch reads src on every handshake and may start with an empty
// set (every steady peer is then refused). Both configs are built once here;
// freshness of the authorized set comes from src, not from rebuilding.
//
// Not wired into any production listener.
func ListenTLSWithPairing(key ed25519.PrivateKey, src AllowedSource, pairingOpen func() bool) (*tls.Config, error) {
	if len(key) != ed25519.PrivateKeySize || src == nil || pairingOpen == nil {
		return nil, errors.New("identity: pairing listener needs an Ed25519 key, an allowed-pin source and a window predicate")
	}
	steady, err := pinningTLSFrom(key, modeListen, src, true)
	if err != nil {
		return nil, err
	}
	pairing, err := PairingTLS(key)
	if err != nil {
		return nil, err
	}
	return ListenTLSWithPairingConfig(func() (*tls.Config, error) { return steady, nil }, pairing, pairingOpen)
}
