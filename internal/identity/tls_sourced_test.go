/**
 * @spec-handoff
 * @interface type AllowedSource func() map[string]struct{}  // called once per handshake, concurrently; result read-only; nil/empty rejects every peer
 * @interface AgentListenTLSFrom(key ed25519.PrivateKey, src AllowedSource) (*tls.Config, error); AgentDialTLSFrom(key ed25519.PrivateKey, src AllowedSource) (*tls.Config, error)
 * @interface PairingTLS(key ed25519.PrivateKey) (*tls.Config, error); ListenTLSWithPairing(key ed25519.PrivateKey, src AllowedSource, pairingOpen func() bool) (*tls.Config, error)
 * @interface ClientListenTLS(key ed25519.PrivateKey, expectedServerPins ...string) (*tls.Config, error); var errSeamBadPairing
 * @behavior
 *   - *From: same shape as AgentListenTLS/AgentDialTLS; src read on every handshake (exactly once each), so a change is seen by the next handshake
 *   - PairingTLS: TLS1.3, NextProtos exactly {quic-link/pair1}, RequireAnyClientCert, tickets off, VerifyConnection set; VerifyPeerCertificate only parses the leaf
 *   - ListenTLSWithPairing: a composition over ListenTLSWithPairingConfig; pair1 offered + window open -> pairing config, else steady; steady reads src per handshake and may start empty
 *   - ClientListenTLS: one pin unchanged; any listed pin accepted, others ErrPinMismatch
 *   - every pinning and pairing config refuses a resumed connection in VerifyConnection (DidResume -> error)
 *   - checkAuthenticating rejects KeyLogWriter (pairing at build, steady per handshake); a dispatcher given an invalid pairing config always fails with errSeamBadPairing
 * @edge-cases
 *   - *From: nil src -> error; src() nil/empty -> the existing empty-set error; "" key -> the existing empty-element error
 *   - at handshake: src nil/empty -> ErrPinMismatch; src panics -> error, the panic never escapes (never allow-all)
 *   - ListenTLSWithPairing: nil key, src or predicate -> (nil, error)
 * @see ./tls.go
 */
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// ---- harness ----------------------------------------------------------------

// liveSet is a mutable authorized set exposed as an AllowedSource. set
// replaces the map instead of mutating it, honoring the read-only contract.
type liveSet struct {
	mu    sync.Mutex
	m     map[string]struct{}
	calls atomic.Int32
	boom  atomic.Bool // when set, the source panics
	isNil atomic.Bool // when set, the source returns a nil map
}

func newLiveSet(pins ...string) *liveSet {
	l := &liveSet{}
	l.set(pins...)
	return l
}

func (l *liveSet) set(pins ...string) {
	m := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		m[p] = struct{}{}
	}
	l.mu.Lock()
	l.m = m
	l.mu.Unlock()
}

func (l *liveSet) source() AllowedSource {
	return func() map[string]struct{} {
		l.calls.Add(1)
		if l.boom.Load() {
			panic("allowed-pin source exploded")
		}
		if l.isNil.Load() {
			return nil
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.m
	}
}

// loopListen serves conf on a loopback QUIC listener for the test's lifetime.
func loopListen(t *testing.T, conf *tls.Config) *quic.Listener {
	t.Helper()
	tr := &quic.Transport{Conn: resumptionLoopbackUDP(t)}
	t.Cleanup(func() { tr.Close() })
	ln, err := tr.Listen(conf, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func loopDialer(t *testing.T) *quic.Transport {
	t.Helper()
	tr := &quic.Transport{Conn: resumptionLoopbackUDP(t)}
	t.Cleanup(func() { tr.Close() })
	return tr
}

// attempt runs one handshake against ln and reports whether BOTH sides
// completed it. A rejection by either side is false: a dialer-side rejection
// fails Dial; a listener-side rejection never yields an accepted connection
// and closes the dialer's connection. Both connections are kept open until
// cleanup, because a session ticket arrives post-handshake.
func attempt(t *testing.T, ln *quic.Listener, dialer *quic.Transport, cliConf *tls.Config) (bool, tls.ConnectionState, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	acceptc := make(chan *quic.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := ln.Accept(ctx); err == nil {
			acceptc <- c
		}
	}()
	defer func() { cancel(); <-done }()

	conn, err := dialer.Dial(ctx, ln.Addr(), cliConf, nil)
	if err != nil {
		return false, tls.ConnectionState{}, err
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	select {
	case srv := <-acceptc:
		t.Cleanup(func() { srv.CloseWithError(0, "") })
		return true, conn.ConnectionState().TLS, nil
	case <-conn.Context().Done():
		return false, conn.ConnectionState().TLS, context.Cause(conn.Context())
	case <-ctx.Done():
		t.Fatal("handshake outcome undetermined within 5s")
		return false, tls.ConnectionState{}, nil
	}
}

func carrierDER(t *testing.T, key ed25519.PrivateKey) [][]byte {
	t.Helper()
	c, err := SelfSignedCarrier(key)
	if err != nil {
		t.Fatalf("SelfSignedCarrier: %v", err)
	}
	return c.Certificate
}

// noPanic calls fn and turns an escaped panic into a test failure.
func noPanic(t *testing.T, what string, fn func() error) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panic escaped: %v", what, r)
			err = errors.New("panicked")
		}
	}()
	return fn()
}

// ---- AllowedSource and the *From constructors --------------------------------

func TestAgentListenTLSFrom_ReadsSourcePerHandshake(t *testing.T) {
	srvKey, cliKey := matrixKey(t), matrixKey(t)
	srvPin, cliPin, otherPin := matrixPin(t, srvKey), matrixPin(t, cliKey), matrixPin(t, matrixKey(t))
	live := newLiveSet(cliPin)
	srvConf, err := AgentListenTLSFrom(srvKey, live.source())
	if err != nil {
		t.Fatalf("AgentListenTLSFrom: %v", err)
	}
	cliConf, err := ClientDialTLS(cliKey, srvPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	ln, dialer := loopListen(t, srvConf), loopDialer(t)

	for _, step := range []struct {
		name string
		pins []string
		want bool
	}{
		{"client in set", []string{cliPin}, true},
		{"client removed", []string{otherPin}, false},
		{"client re-added", []string{otherPin, cliPin}, true},
	} {
		live.set(step.pins...)
		before := live.calls.Load()
		got, _, err := attempt(t, ln, dialer, cliConf)
		if got != step.want {
			t.Errorf("%s: handshake completed = %v (err %v), want %v", step.name, got, err, step.want)
		}
		if d := live.calls.Load() - before; d != 1 {
			t.Errorf("%s: source called %d times during one handshake, want 1", step.name, d)
		}
	}
}

func TestAgentDialTLSFrom_ReadsSourcePerHandshake(t *testing.T) {
	agentKey, cliKey := matrixKey(t), matrixKey(t)
	agentPin, cliPin, otherPin := matrixPin(t, agentKey), matrixPin(t, cliKey), matrixPin(t, matrixKey(t))
	srvConf, err := ClientListenTLS(cliKey, agentPin)
	if err != nil {
		t.Fatalf("ClientListenTLS: %v", err)
	}
	live := newLiveSet(cliPin)
	dialConf, err := AgentDialTLSFrom(agentKey, live.source())
	if err != nil {
		t.Fatalf("AgentDialTLSFrom: %v", err)
	}
	ln, dialer := loopListen(t, srvConf), loopDialer(t)

	for _, step := range []struct {
		name string
		pins []string
		want bool
	}{
		{"client in set", []string{cliPin}, true},
		{"client removed", []string{otherPin}, false},
		{"client re-added", []string{otherPin, cliPin}, true},
	} {
		live.set(step.pins...)
		before := live.calls.Load()
		got, _, err := attempt(t, ln, dialer, dialConf)
		if got != step.want {
			t.Errorf("%s: handshake completed = %v (err %v), want %v", step.name, got, err, step.want)
		}
		if d := live.calls.Load() - before; d != 1 {
			t.Errorf("%s: source called %d times during one handshake, want 1", step.name, d)
		}
	}
}

func TestFromConstructors_RejectNilOrEmptySourceAtBuild(t *testing.T) {
	key := matrixKey(t)
	pin := matrixPin(t, matrixKey(t))
	_, setErr := AgentListenTLS(key, nil)
	_, elemErr := AgentListenTLS(key, []string{""})
	if setErr == nil || elemErr == nil {
		t.Fatalf("reference errors missing: set=%v elem=%v", setErr, elemErr)
	}
	src := func(m map[string]struct{}) AllowedSource { return func() map[string]struct{} { return m } }

	for name, build := range map[string]func(ed25519.PrivateKey, AllowedSource) (*tls.Config, error){
		"AgentListenTLSFrom": AgentListenTLSFrom,
		"AgentDialTLSFrom":   AgentDialTLSFrom,
	} {
		t.Run(name, func(t *testing.T) {
			if cfg, err := build(key, src(map[string]struct{}{pin: {}})); err != nil || cfg == nil {
				t.Errorf("control: non-empty source rejected: cfg set=%v err=%v", cfg != nil, err)
			}
			if cfg, err := build(key, nil); err == nil || cfg != nil {
				t.Errorf("nil source: cfg set=%v err=%v, want nil config and an error", cfg != nil, err)
			}
			for what, tc := range map[string]struct {
				m    map[string]struct{}
				want error
			}{
				"source returns nil":        {nil, setErr},
				"source returns empty":      {map[string]struct{}{}, setErr},
				"source has an empty pin":   {map[string]struct{}{"": {}}, elemErr},
				"source mixes empty, valid": {map[string]struct{}{"": {}, pin: {}}, elemErr},
			} {
				cfg, err := build(key, src(tc.m))
				if cfg != nil || err == nil || err.Error() != tc.want.Error() {
					t.Errorf("%s: cfg set=%v err=%v, want nil config and %q", what, cfg != nil, err, tc.want)
				}
			}
		})
	}
}

func TestSourcedVerify_EmptyNilOrPanickingSourceRejectsEveryPeer(t *testing.T) {
	key, peerKey := matrixKey(t), matrixKey(t)
	peerPin, otherPin := matrixPin(t, peerKey), matrixPin(t, matrixKey(t))
	peer := carrierDER(t, peerKey)

	// Each builder returns a function yielding the config used for one
	// handshake; for ListenTLSWithPairing that is the steady branch.
	builders := map[string]func(*testing.T, AllowedSource) func() *tls.Config{
		"AgentListenTLSFrom": func(t *testing.T, s AllowedSource) func() *tls.Config {
			cfg, err := AgentListenTLSFrom(key, s)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			return func() *tls.Config { return cfg }
		},
		"AgentDialTLSFrom": func(t *testing.T, s AllowedSource) func() *tls.Config {
			cfg, err := AgentDialTLSFrom(key, s)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			return func() *tls.Config { return cfg }
		},
		"ListenTLSWithPairing steady branch": func(t *testing.T, s AllowedSource) func() *tls.Config {
			outer, err := ListenTLSWithPairing(key, s, always(false))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			return func() *tls.Config {
				cfg, err := callSeam(t, outer.GetConfigForClient, hello(transport.ALPN))
				if err != nil || cfg == nil {
					t.Fatalf("steady branch: cfg set=%v err=%v", cfg != nil, err)
				}
				return cfg
			}
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			live := newLiveSet(peerPin)
			conf := build(t, live.source())
			verify := func() error {
				return noPanic(t, "VerifyPeerCertificate", func() error { return conf().VerifyPeerCertificate(peer, nil) })
			}

			if err := verify(); err != nil {
				t.Fatalf("control: peer in set rejected: %v", err)
			}
			live.set(otherPin)
			if err := verify(); !errors.Is(err, ErrPinMismatch) {
				t.Errorf("peer not in set: err = %v, want ErrPinMismatch", err)
			}
			live.set()
			if err := verify(); !errors.Is(err, ErrPinMismatch) {
				t.Errorf("empty set: err = %v, want ErrPinMismatch (never allow-all)", err)
			}
			live.isNil.Store(true)
			if err := verify(); !errors.Is(err, ErrPinMismatch) {
				t.Errorf("nil set: err = %v, want ErrPinMismatch (never allow-all)", err)
			}
			live.isNil.Store(false)
			live.set(peerPin)
			live.boom.Store(true)
			if err := verify(); err == nil {
				t.Error("panicking source: peer accepted, want an error (fail closed)")
			}
		})
	}
}

// ---- PairingTLS ----------------------------------------------------------------

func TestPairingTLS_Shape(t *testing.T) {
	key := matrixKey(t)
	cfg, err := PairingTLS(key)
	if err != nil {
		t.Fatalf("PairingTLS: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	if !slices.Equal(cfg.NextProtos, []string{"quic-link/pair1"}) {
		t.Errorf("NextProtos = %q, want exactly [quic-link/pair1]", cfg.NextProtos)
	}
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", cfg.ClientAuth)
	}
	if !cfg.SessionTicketsDisabled {
		t.Error("SessionTicketsDisabled = false: resumption would skip the peer check")
	}
	if cfg.VerifyPeerCertificate == nil || cfg.VerifyConnection == nil {
		t.Errorf("VerifyPeerCertificate set = %v, VerifyConnection set = %v, want both",
			cfg.VerifyPeerCertificate != nil, cfg.VerifyConnection != nil)
	}
	if cfg.InsecureSkipVerify || cfg.KeyLogWriter != nil || cfg.GetConfigForClient != nil || cfg.GetCertificate != nil {
		t.Errorf("unexpected knobs: InsecureSkipVerify=%v KeyLogWriter=%v GetConfigForClient=%v GetCertificate=%v",
			cfg.InsecureSkipVerify, cfg.KeyLogWriter != nil, cfg.GetConfigForClient != nil, cfg.GetCertificate != nil)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf == nil {
		t.Fatalf("Certificates = %d (leaf parsed: %v), want exactly one carrier", len(cfg.Certificates),
			len(cfg.Certificates) == 1 && cfg.Certificates[0].Leaf != nil)
	}
	if got, want := PinFromCert(cfg.Certificates[0].Leaf), matrixPin(t, key); got != want {
		t.Errorf("carrier pin = %s, want the key's pin %s", got, want)
	}
	if err := checkAuthenticating(cfg); err != nil {
		t.Errorf("checkAuthenticating: %v", err)
	}
	if _, err := ListenTLSWithPairingConfig(func() (*tls.Config, error) { return nil, nil }, cfg, always(false)); err != nil {
		t.Errorf("the pairing seam rejects PairingTLS output: %v", err)
	}
}

func TestPairingTLS_VerifyOnlyRequiresParsableLeaf(t *testing.T) {
	cfg, err := PairingTLS(matrixKey(t))
	if err != nil {
		t.Fatalf("PairingTLS: %v", err)
	}
	stranger := carrierDER(t, matrixKey(t))
	for name, raw := range map[string][][]byte{
		"unknown peer carrier":             stranger,
		"valid leaf followed by junk":      {stranger[0], []byte("junk")},
		"another unknown peer carrier":     carrierDER(t, matrixKey(t)),
		"leaf repeated (chain not walked)": {stranger[0], stranger[0]},
	} {
		if err := cfg.VerifyPeerCertificate(raw, nil); err != nil {
			t.Errorf("%s: rejected: %v (pairing must accept any parsable leaf)", name, err)
		}
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); !errors.Is(err, ErrNoPeerCert) {
		t.Errorf("no certificate: err = %v, want ErrNoPeerCert", err)
	}
	err = cfg.VerifyPeerCertificate([][]byte{[]byte("not DER")}, nil)
	if err == nil || errors.Is(err, ErrPinMismatch) || errors.Is(err, ErrNoPeerCert) {
		t.Errorf("garbage leaf: err = %v, want a parse error", err)
	}
}

// ---- ListenTLSWithPairing ---------------------------------------------------------

func TestListenTLSWithPairing_SelectsConfigByOfferedALPNAndWindow(t *testing.T) {
	srvKey, cliKey := matrixKey(t), matrixKey(t)
	srvPin, cliPin := matrixPin(t, srvKey), matrixPin(t, cliKey)
	stranger := carrierDER(t, matrixKey(t))
	var open atomic.Bool
	outer, err := ListenTLSWithPairing(srvKey, newLiveSet(cliPin).source(), open.Load)
	if err != nil {
		t.Fatalf("ListenTLSWithPairing: %v", err)
	}
	if outer.GetConfigForClient == nil || len(outer.Certificates) != 0 || !slices.Equal(outer.NextProtos, steadyALPN) {
		t.Fatalf("outer config: GetConfigForClient set=%v Certificates=%d NextProtos=%q",
			outer.GetConfigForClient != nil, len(outer.Certificates), outer.NextProtos)
	}

	for _, tc := range []struct {
		name        string
		protos      []string
		open        bool
		wantPairing bool
	}{
		{"steady, open", []string{transport.ALPN}, true, false},
		{"steady, closed", []string{transport.ALPN}, false, false},
		{"pair1, open", []string{alpnPair1}, true, true},
		{"pair1, closed", []string{alpnPair1}, false, false},
		{"both, open", []string{transport.ALPN, alpnPair1}, true, true},
		{"both, closed", []string{transport.ALPN, alpnPair1}, false, false},
		{"none, open", nil, true, false},
		{"unknown, open", []string{"h3"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			open.Store(tc.open)
			cfg, err := callSeam(t, outer.GetConfigForClient, hello(tc.protos...))
			if err != nil || cfg == nil {
				t.Fatalf("cfg set=%v err=%v", cfg != nil, err)
			}
			wantALPN, wantVerify := steadyALPN, error(ErrPinMismatch)
			if tc.wantPairing {
				wantALPN, wantVerify = pairingALPN, nil
			}
			if !slices.Equal(cfg.NextProtos, wantALPN) {
				t.Errorf("NextProtos = %q, want %q", cfg.NextProtos, wantALPN)
			}
			// The branches differ in who they admit: pairing admits any
			// parsable peer, steady only authorized pins.
			if err := cfg.VerifyPeerCertificate(stranger, nil); !errors.Is(err, wantVerify) {
				t.Errorf("unknown peer: err = %v, want %v", err, wantVerify)
			}
		})
	}

	t.Run("handshake: pair1 with the window open negotiates pair1 for an unknown peer", func(t *testing.T) {
		open.Store(true)
		ln, dialer := loopListen(t, outer), loopDialer(t)
		base, err := ClientDialTLS(matrixKey(t), srvPin)
		if err != nil {
			t.Fatalf("ClientDialTLS: %v", err)
		}
		cli := base.Clone()
		cli.NextProtos = []string{alpnPair1}
		ok, cs, err := attempt(t, ln, dialer, cli)
		if !ok || cs.NegotiatedProtocol != alpnPair1 {
			t.Errorf("completed=%v NegotiatedProtocol=%q err=%v, want completed on %q", ok, cs.NegotiatedProtocol, err, alpnPair1)
		}
	})

	t.Run("handshake: pair1 with the window closed fails at ALPN", func(t *testing.T) {
		open.Store(false)
		ln, dialer := loopListen(t, outer), loopDialer(t)
		base, err := ClientDialTLS(cliKey, srvPin)
		if err != nil {
			t.Fatalf("ClientDialTLS: %v", err)
		}
		cli := base.Clone()
		cli.NextProtos = []string{alpnPair1}
		ok, _, err := attempt(t, ln, dialer, cli)
		var te *quic.TransportError
		if ok || !errors.As(err, &te) || te.ErrorCode != 0x178 {
			t.Errorf("completed=%v err=%v, want a no_application_protocol failure (0x178)", ok, err)
		}
	})
}

func TestListenTLSWithPairing_EveryReturnedConfigDisablesTickets(t *testing.T) {
	key := matrixKey(t)
	var open atomic.Bool
	outer, err := ListenTLSWithPairing(key, newLiveSet(matrixPin(t, matrixKey(t))).source(), open.Load)
	if err != nil {
		t.Fatalf("ListenTLSWithPairing: %v", err)
	}
	if !outer.SessionTicketsDisabled {
		t.Error("outer SessionTicketsDisabled = false")
	}
	for _, o := range []bool{false, true} {
		for _, protos := range [][]string{{transport.ALPN}, {alpnPair1}, {alpnPair1, transport.ALPN}, nil} {
			open.Store(o)
			cfg, err := callSeam(t, outer.GetConfigForClient, hello(protos...))
			if err != nil || cfg == nil {
				t.Errorf("open=%v offer %q: cfg set=%v err=%v", o, protos, cfg != nil, err)
				continue
			}
			if !cfg.SessionTicketsDisabled {
				t.Errorf("open=%v offer %q: SessionTicketsDisabled = false", o, protos)
			}
			if cfg.VerifyConnection == nil {
				t.Errorf("open=%v offer %q: VerifyConnection is nil", o, protos)
			}
			if cfg.GetConfigForClient != nil {
				t.Errorf("open=%v offer %q: returned config nests GetConfigForClient", o, protos)
			}
		}
	}
}

func TestListenTLSWithPairing_SteadyBranchStartsEmptyAndReadsSource(t *testing.T) {
	srvKey, cliKey := matrixKey(t), matrixKey(t)
	srvPin, cliPin := matrixPin(t, srvKey), matrixPin(t, cliKey)
	live := newLiveSet()
	outer, err := ListenTLSWithPairing(srvKey, live.source(), always(false))
	if err != nil {
		t.Fatalf("ListenTLSWithPairing with an empty set must build: %v", err)
	}
	cliConf, err := ClientDialTLS(cliKey, srvPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	ln, dialer := loopListen(t, outer), loopDialer(t)

	if ok, _, err := attempt(t, ln, dialer, cliConf); ok {
		t.Errorf("empty set admitted a steady peer (err %v): an empty set must reject everyone", err)
	}
	live.set(cliPin)
	if ok, _, err := attempt(t, ln, dialer, cliConf); !ok {
		t.Errorf("pin added to the source not seen by the next handshake: %v", err)
	}
	live.set()
	if ok, _, err := attempt(t, ln, dialer, cliConf); ok {
		t.Errorf("pin removed from the source still admitted (err %v)", err)
	}
}

func TestListenTLSWithPairing_RejectsNilInputs(t *testing.T) {
	key := matrixKey(t)
	src := newLiveSet(matrixPin(t, matrixKey(t))).source()
	if cfg, err := ListenTLSWithPairing(key, src, always(false)); err != nil || cfg == nil {
		t.Fatalf("control: valid inputs rejected: cfg set=%v err=%v", cfg != nil, err)
	}
	for name, tc := range map[string]struct {
		key  ed25519.PrivateKey
		src  AllowedSource
		open func() bool
	}{
		"nil key":       {nil, src, always(false)},
		"nil source":    {key, nil, always(false)},
		"nil predicate": {key, src, nil},
	} {
		cfg, err := noPanicBuild(t, name, func() (*tls.Config, error) { return ListenTLSWithPairing(tc.key, tc.src, tc.open) })
		if err == nil || cfg != nil {
			t.Errorf("%s: cfg set=%v err=%v, want nil config and an error", name, cfg != nil, err)
		}
	}
}

func noPanicBuild(t *testing.T, what string, fn func() (*tls.Config, error)) (cfg *tls.Config, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panic escaped: %v", what, r)
			cfg, err = nil, errors.New("panicked")
		}
	}()
	return fn()
}

// ---- ClientListenTLS pin set ------------------------------------------------------

func TestClientListenTLS_AcceptsAnyPinInSetOnly(t *testing.T) {
	srvKey := matrixKey(t)
	srvPin := matrixPin(t, srvKey)
	agents := map[string]ed25519.PrivateKey{"a": matrixKey(t), "b": matrixKey(t), "c": matrixKey(t)}
	pin := func(n string) string { return matrixPin(t, agents[n]) }

	for _, tc := range []struct {
		name   string
		pins   []string
		admits map[string]bool
	}{
		{"single pin unchanged", []string{pin("a")}, map[string]bool{"a": true, "b": false, "c": false}},
		{"two pins", []string{pin("a"), pin("b")}, map[string]bool{"a": true, "b": true, "c": false}},
		{"two pins, other order", []string{pin("b"), pin("a")}, map[string]bool{"a": true, "b": true, "c": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvConf, err := ClientListenTLS(srvKey, tc.pins...)
			if err != nil {
				t.Fatalf("ClientListenTLS: %v", err)
			}
			ln, dialer := loopListen(t, srvConf), loopDialer(t)
			for _, n := range []string{"a", "b", "c"} {
				cli, err := AgentDialTLS(agents[n], []string{srvPin})
				if err != nil {
					t.Fatalf("AgentDialTLS: %v", err)
				}
				if ok, _, err := attempt(t, ln, dialer, cli); ok != tc.admits[n] {
					t.Errorf("agent %s: handshake completed = %v (err %v), want %v", n, ok, err, tc.admits[n])
				}
				err = srvConf.VerifyPeerCertificate(carrierDER(t, agents[n]), nil)
				if tc.admits[n] && err != nil {
					t.Errorf("agent %s: VerifyPeerCertificate = %v, want nil", n, err)
				}
				if !tc.admits[n] && !errors.Is(err, ErrPinMismatch) {
					t.Errorf("agent %s: VerifyPeerCertificate = %v, want ErrPinMismatch", n, err)
				}
			}
		})
	}
}

// ---- carried seam fixes ---------------------------------------------------------

func TestPairingSeam_RejectsKeyLogWriter(t *testing.T) {
	f := newSeamFixture(t)

	t.Run("pairing config at build", func(t *testing.T) {
		if _, err := ListenTLSWithPairingConfig(f.source(), f.pairing.Clone(), always(true)); err != nil {
			t.Fatalf("control: valid pairing config rejected: %v", err)
		}
		p := f.pairing.Clone()
		p.KeyLogWriter = io.Discard
		if cfg, err := ListenTLSWithPairingConfig(f.source(), p, always(true)); err == nil || cfg != nil {
			t.Errorf("pairing config with KeyLogWriter: cfg set=%v err=%v, want nil config and an error", cfg != nil, err)
		}
	})

	t.Run("steady config per handshake", func(t *testing.T) {
		if cfg, err := callSeam(t, pairingDispatcher(f.source(), f.pairing, always(false)), hello(transport.ALPN)); err != nil || cfg == nil {
			t.Fatalf("control: valid steady config rejected: cfg set=%v err=%v", cfg != nil, err)
		}
		bad := f.steady.Clone()
		bad.KeyLogWriter = io.Discard
		src := func() (*tls.Config, error) { return bad, nil }
		cfg, err := callSeam(t, pairingDispatcher(src, f.pairing, always(false)), hello(transport.ALPN))
		if cfg != nil || !errors.Is(err, errSeamBadSteady) {
			t.Errorf("steady config with KeyLogWriter: cfg set=%v err=%v, want nil and errSeamBadSteady", cfg != nil, err)
		}
	})
}

func TestPairingDispatcher_InvalidPairingConfigFailsClosed(t *testing.T) {
	f := newSeamFixture(t)
	if cfg, err := callSeam(t, pairingDispatcher(f.source(), f.pairing, always(true)), hello(alpnPair1)); err != nil || cfg == nil {
		t.Fatalf("control: valid pairing config: cfg set=%v err=%v", cfg != nil, err)
	}
	mut := func(m func(*tls.Config)) *tls.Config {
		c := f.pairing.Clone()
		m(c)
		return c
	}
	for name, bad := range map[string]*tls.Config{
		"advertises steady ALPN":        mut(func(c *tls.Config) { c.NextProtos = []string{transport.ALPN} }),
		"advertises pair1 and steady":   mut(func(c *tls.Config) { c.NextProtos = []string{alpnPair1, transport.ALPN} }),
		"no pin callback":               mut(func(c *tls.Config) { c.VerifyPeerCertificate = nil }),
		"peer certificate not required": mut(func(c *tls.Config) { c.ClientAuth = tls.NoClientCert }),
		"below TLS 1.3":                 mut(func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }),
		"KeyLogWriter set":              mut(func(c *tls.Config) { c.KeyLogWriter = io.Discard }),
	} {
		t.Run(name, func(t *testing.T) {
			cb := pairingDispatcher(f.source(), bad, always(true))
			for _, h := range []*tls.ClientHelloInfo{hello(alpnPair1), hello(transport.ALPN)} {
				cfg, err := callSeam(t, cb, h)
				if cfg != nil || !errors.Is(err, errSeamBadPairing) {
					t.Errorf("offer %q: cfg set=%v err=%v, want nil and errSeamBadPairing", h.SupportedProtos, cfg != nil, err)
				}
			}
		})
	}
}

// TestListenTLSWithPairingConfig_ValidatesSnapshot pins the post-condition of
// snapshot-then-validate: once built, no edit of the caller's pairing config
// reaches a returned config. The order itself (snapshot first, then check the
// snapshot) has no deterministic hook; it is held by review.
func TestListenTLSWithPairingConfig_ValidatesSnapshot(t *testing.T) {
	f := newSeamFixture(t)
	p := f.pairing.Clone()
	p.NextProtos = []string{alpnPair1}
	outer, err := ListenTLSWithPairingConfig(f.source(), p, always(true))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	p.NextProtos[0] = transport.ALPN
	p.ClientAuth = tls.NoClientCert
	p.VerifyPeerCertificate = nil
	p.VerifyConnection = nil
	p.MinVersion = tls.VersionTLS12
	p.KeyLogWriter = io.Discard
	p.SessionTicketsDisabled = false
	p.Certificates = nil
	p.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }

	cfg, err := callSeam(t, outer.GetConfigForClient, hello(alpnPair1))
	if err != nil || cfg == nil {
		t.Fatalf("cfg set=%v err=%v", cfg != nil, err)
	}
	if !slices.Equal(cfg.NextProtos, pairingALPN) {
		t.Errorf("NextProtos = %q, want %q", cfg.NextProtos, pairingALPN)
	}
	if err := checkAuthenticating(cfg); err != nil {
		t.Errorf("caller edit reached the returned pairing config: %v", err)
	}
	if cfg.KeyLogWriter != nil || !cfg.SessionTicketsDisabled {
		t.Errorf("caller edit reached the returned pairing config: KeyLogWriter set=%v SessionTicketsDisabled=%v",
			cfg.KeyLogWriter != nil, cfg.SessionTicketsDisabled)
	}
}

// ---- resumption guard -----------------------------------------------------------

// TestPinningConfigs_RejectResumedConnection proves the second guard against
// resumption: with tickets deliberately re-enabled on test-only copies, a
// pinning listener or dialer still refuses the resumed second connection,
// because a resumed handshake never runs VerifyPeerCertificate. The control
// clears VerifyConnection on both sides and shows the same setup does resume,
// so the refusals are not an artifact of a harness that cannot resume.
func TestPinningConfigs_RejectResumedConnection(t *testing.T) {
	t.Run("every pinning and pairing config refuses DidResume", func(t *testing.T) {
		key := matrixKey(t)
		pin := matrixPin(t, matrixKey(t))
		src := newLiveSet(pin).source()
		for name, build := range map[string]func() (*tls.Config, error){
			"ClientDialTLS":      func() (*tls.Config, error) { return ClientDialTLS(key, pin) },
			"ClientListenTLS":    func() (*tls.Config, error) { return ClientListenTLS(key, pin) },
			"AgentListenTLS":     func() (*tls.Config, error) { return AgentListenTLS(key, []string{pin}) },
			"AgentDialTLS":       func() (*tls.Config, error) { return AgentDialTLS(key, []string{pin}) },
			"AgentListenTLSFrom": func() (*tls.Config, error) { return AgentListenTLSFrom(key, src) },
			"AgentDialTLSFrom":   func() (*tls.Config, error) { return AgentDialTLSFrom(key, src) },
			"PairingTLS":         func() (*tls.Config, error) { return PairingTLS(key) },
		} {
			cfg, err := build()
			if err != nil {
				t.Errorf("%s: build: %v", name, err)
				continue
			}
			if cfg.VerifyConnection == nil {
				t.Errorf("%s: VerifyConnection is nil", name)
				continue
			}
			if err := cfg.VerifyConnection(tls.ConnectionState{DidResume: true}); err == nil {
				t.Errorf("%s: VerifyConnection accepted a resumed connection", name)
			}
			if err := cfg.VerifyConnection(tls.ConnectionState{}); err != nil {
				t.Errorf("%s: VerifyConnection refused a fresh connection: %v", name, err)
			}
		}
	})

	type pair struct {
		listen, dial func(t *testing.T) *tls.Config
	}
	srvKey, cliKey := matrixKey(t), matrixKey(t)
	srvPin, cliPin := matrixPin(t, srvKey), matrixPin(t, cliKey)
	must := func(t *testing.T, c *tls.Config, err error) *tls.Config {
		t.Helper()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return c
	}
	pairs := map[string]pair{
		"agent listens, client dials": {
			listen: func(t *testing.T) *tls.Config {
				c, err := AgentListenTLS(srvKey, []string{cliPin})
				return must(t, c, err)
			},
			dial: func(t *testing.T) *tls.Config { c, err := ClientDialTLS(cliKey, srvPin); return must(t, c, err) },
		},
		"client listens, agent dials": {
			listen: func(t *testing.T) *tls.Config { c, err := ClientListenTLS(srvKey, cliPin); return must(t, c, err) },
			dial: func(t *testing.T) *tls.Config {
				c, err := AgentDialTLS(cliKey, []string{srvPin})
				return must(t, c, err)
			},
		},
	}
	for pname, p := range pairs {
		for _, tc := range []struct {
			name                    string
			guardListen, guardDial  bool
			wantSecondDialCompletes bool
		}{
			{"control: both guards cleared, second dial resumes", false, false, true},
			{"both guarded", true, true, false},
			{"listener guarded only", true, false, false},
			{"dialer guarded only", false, true, false},
		} {
			t.Run(pname+"/"+tc.name, func(t *testing.T) {
				// TEST-ONLY copies: tickets re-enabled on both sides and a
				// cache on the dialer, which pinning output never has.
				lc, dc := p.listen(t), p.dial(t)
				lc.SessionTicketsDisabled, dc.SessionTicketsDisabled = false, false
				if !tc.guardListen {
					lc.VerifyConnection = nil
				}
				if !tc.guardDial {
					dc.VerifyConnection = nil
				}
				putc := make(chan struct{}, 1)
				dc.ClientSessionCache = &resumptionPutSignalCache{ClientSessionCache: tls.NewLRUClientSessionCache(1), putc: putc}
				ln, dialer := loopListen(t, lc), loopDialer(t)

				if ok, cs, err := attempt(t, ln, dialer, dc); !ok || cs.DidResume {
					t.Fatalf("first dial: completed=%v resumed=%v err=%v, want a fresh handshake", ok, cs.DidResume, err)
				}
				select {
				case <-putc:
				case <-time.After(5 * time.Second):
					t.Fatal("no session ticket stored within 5s: this setup cannot attempt resumption")
				}
				ok, cs, err := attempt(t, ln, dialer, dc)
				if tc.wantSecondDialCompletes {
					if !ok || !cs.DidResume {
						t.Fatalf("control: second dial completed=%v resumed=%v err=%v, want a resumed connection", ok, cs.DidResume, err)
					}
					return
				}
				if ok {
					t.Errorf("resumed second connection was accepted (DidResume=%v): VerifyConnection must refuse it", cs.DidResume)
				}
			})
		}
	}
}
