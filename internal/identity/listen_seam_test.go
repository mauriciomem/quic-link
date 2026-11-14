/**
 * @spec-handoff
 * @interface pinningTLS(key ed25519.PrivateKey, mode transportMode, allowed []string, allowEmptyAtStart bool) (*tls.Config, error)
 * @interface pairingDispatcher(steady configSource, pairing *tls.Config, pairingOpen func() bool) func(*tls.ClientHelloInfo) (*tls.Config, error); type configSource func() (*tls.Config, error); const alpnPair1 = "quic-link/pair1"
 * @interface ListenTLSWithPairingConfig(steady func() (*tls.Config, error), pairing *tls.Config, pairingOpen func() bool) (*tls.Config, error)  // exported, unwired
 * @interface routeFor(cs tls.ConnectionState) listenRoute; routeReject | routeSteady | routePairing
 * @behavior
 *   - pair1 offered AND pairingOpen() -> pairing snapshot, NextProtos exactly {pair1}; otherwise steady() clone with NextProtos {quic-link/1}
 *   - every returned config is a clone with SessionTicketsDisabled=true, GetConfigForClient=nil; outer config: NextProtos {quic-link/1}, TLS1.3, tickets off, no Certificates
 *   - total: never (nil,nil); nil hello -> errSeamNoHello; steady nil -> errSeamNilConfig; steady not a pinning listener (checkSteady) -> errSeamBadSteady; any panic -> errSeamPanic; steady error wrapped
 *   - pairingOpen is evaluated only when pair1 is offered; routeFor reads NegotiatedProtocol only
 * @edge-cases
 *   - allowEmptyAtStart=true + empty set builds but rejects every peer with ErrPinMismatch; "" element still refused; exported constructors unchanged
 *   - build rejects nil args and a pairing config with NextProtos != {pair1}, no RequireAnyClientCert, no VerifyPeerCertificate, != 1 cert, GetConfigForClient or GetCertificate set, or MinVersion < TLS 1.3
 *   - steady config with GetCertificate set -> errSeamBadSteady; the steady config is cloned before it is validated
 *   - no aliasing: in-place edits of the caller's NextProtos/Certificates (pairing or steady) never reach a returned config; returned NextProtos are not shared between calls
 * @see ./tls.go
 */
package identity

import (
	"crypto/tls"
	"errors"
	"slices"
	"testing"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// seamFixture holds one listener identity: a steady pinning listener config
// and a pairing config derived from it that differs only in ALPN.
type seamFixture struct {
	steady  *tls.Config
	pairing *tls.Config
	peerRaw []byte // a valid peer leaf certificate (DER) not in any pin set
}

func newSeamFixture(t *testing.T) seamFixture {
	t.Helper()
	key := matrixKey(t)
	peer := matrixKey(t)
	steady, err := AgentListenTLS(key, []string{matrixPin(t, peer)})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	pairing := steady.Clone()
	pairing.NextProtos = []string{alpnPair1}
	other, err := SelfSignedCarrier(matrixKey(t))
	if err != nil {
		t.Fatalf("SelfSignedCarrier: %v", err)
	}
	return seamFixture{steady: steady, pairing: pairing, peerRaw: other.Certificate[0]}
}

func (f seamFixture) source() configSource {
	return func() (*tls.Config, error) { return f.steady, nil }
}

func hello(protos ...string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{SupportedProtos: protos}
}

func always(v bool) func() bool { return func() bool { return v } }

// callSeam invokes a dispatcher callback and turns an escaped panic into a
// test failure instead of crashing the binary: the dispatcher must recover.
func callSeam(t *testing.T, cb func(*tls.ClientHelloInfo) (*tls.Config, error), h *tls.ClientHelloInfo) (cfg *tls.Config, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("dispatcher let a panic escape: %v", r)
		}
	}()
	return cb(h)
}

var (
	steadyALPN  = []string{transport.ALPN}
	pairingALPN = []string{"quic-link/pair1"}
)

// TestPairingDispatcher_PairingBranchAdvertisesOnlyPair1 - the pairing branch offers pair1 only.
func TestPairingDispatcher_PairingBranchAdvertisesOnlyPair1(t *testing.T) {
	if alpnPair1 != "quic-link/pair1" {
		t.Fatalf("alpnPair1 = %q, want quic-link/pair1", alpnPair1)
	}
	f := newSeamFixture(t)
	cb := pairingDispatcher(f.source(), f.pairing, always(true))
	for name, h := range map[string]*tls.ClientHelloInfo{
		"pair1 only":         hello(alpnPair1),
		"pair1 and steady":   hello(alpnPair1, transport.ALPN),
		"steady then pair1":  hello(transport.ALPN, alpnPair1),
		"pair1 with unknown": hello("h3", alpnPair1),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := callSeam(t, cb, h)
			if err != nil || cfg == nil {
				t.Fatalf("pairing branch: cfg=%v err=%v", cfg, err)
			}
			if !slices.Equal(cfg.NextProtos, pairingALPN) {
				t.Errorf("NextProtos = %q, want exactly %q", cfg.NextProtos, pairingALPN)
			}
		})
	}

	t.Run("build rejects a pairing config not advertising exactly pair1", func(t *testing.T) {
		for name, protos := range map[string][]string{
			"pair1 plus steady": {alpnPair1, transport.ALPN},
			"empty":             {},
			"nil":               nil,
			"steady only":       {transport.ALPN},
		} {
			p := f.pairing.Clone()
			p.NextProtos = protos
			if _, err := ListenTLSWithPairingConfig(f.source(), p, always(true)); err == nil {
				t.Errorf("%s: build accepted pairing NextProtos %q", name, protos)
			}
		}
	})

	t.Run("pairing config is snapshotted at build", func(t *testing.T) {
		p := f.pairing.Clone()
		outer, err := ListenTLSWithPairingConfig(f.source(), p, always(true))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		p.NextProtos = []string{alpnPair1, transport.ALPN}
		cfg, err := callSeam(t, outer.GetConfigForClient, hello(alpnPair1))
		if err != nil || cfg == nil {
			t.Fatalf("cfg=%v err=%v", cfg, err)
		}
		if !slices.Equal(cfg.NextProtos, pairingALPN) {
			t.Errorf("caller mutation leaked into the seam: NextProtos = %q", cfg.NextProtos)
		}
	})

	t.Run("in-place edits of the caller's slices do not reach the seam", func(t *testing.T) {
		other, err := SelfSignedCarrier(matrixKey(t))
		if err != nil {
			t.Fatalf("SelfSignedCarrier: %v", err)
		}
		p := f.pairing.Clone()
		p.NextProtos = []string{alpnPair1}
		p.Certificates = []tls.Certificate{f.pairing.Certificates[0]}
		wantLeaf := f.pairing.Certificates[0].Certificate[0]

		st := f.steady.Clone()
		st.NextProtos = []string{transport.ALPN}
		st.Certificates = []tls.Certificate{f.steady.Certificates[0]}
		src := func() (*tls.Config, error) { return st, nil }

		outer, err := ListenTLSWithPairingConfig(src, p, always(true))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		pc, err := callSeam(t, outer.GetConfigForClient, hello(alpnPair1))
		if err != nil || pc == nil {
			t.Fatalf("pairing cfg=%v err=%v", pc, err)
		}
		sc, err := callSeam(t, outer.GetConfigForClient, hello(transport.ALPN))
		if err != nil || sc == nil {
			t.Fatalf("steady cfg=%v err=%v", sc, err)
		}

		p.NextProtos[0] = transport.ALPN
		p.Certificates[0] = other
		st.NextProtos[0] = alpnPair1
		st.Certificates[0] = other

		if !slices.Equal(pc.NextProtos, pairingALPN) {
			t.Errorf("pairing config returned before the edit: NextProtos = %q", pc.NextProtos)
		}
		if !slices.Equal(sc.NextProtos, steadyALPN) {
			t.Errorf("steady config returned before the edit: NextProtos = %q", sc.NextProtos)
		}
		for name, c := range map[string]*tls.Config{"pairing": pc, "steady": sc} {
			if len(c.Certificates) != 1 || len(c.Certificates[0].Certificate) == 0 ||
				string(c.Certificates[0].Certificate[0]) != string(wantLeaf) {
				t.Errorf("%s config returned before the edit: certificate changed", name)
			}
		}
		pc2, err := callSeam(t, outer.GetConfigForClient, hello(alpnPair1))
		if err != nil || pc2 == nil {
			t.Fatalf("pairing after edit: cfg=%v err=%v", pc2, err)
		}
		if !slices.Equal(pc2.NextProtos, pairingALPN) ||
			string(pc2.Certificates[0].Certificate[0]) != string(wantLeaf) {
			t.Errorf("caller edit reached a later pairing config: NextProtos = %q", pc2.NextProtos)
		}
	})

	t.Run("returned NextProtos are not shared between calls", func(t *testing.T) {
		cb := pairingDispatcher(f.source(), f.pairing, always(true))
		for name, h := range map[string]*tls.ClientHelloInfo{"pairing": hello(alpnPair1), "steady": hello(transport.ALPN)} {
			a, err := callSeam(t, cb, h)
			if err != nil || a == nil {
				t.Fatalf("%s: cfg=%v err=%v", name, a, err)
			}
			want := slices.Clone(a.NextProtos)
			a.NextProtos[0] = "h3"
			a.Certificates[0] = tls.Certificate{}
			b, err := callSeam(t, cb, h)
			if err != nil || b == nil {
				t.Fatalf("%s: cfg=%v err=%v", name, b, err)
			}
			if !slices.Equal(b.NextProtos, want) {
				t.Errorf("%s: edit of one returned config reached the next: NextProtos = %q", name, b.NextProtos)
			}
			if len(b.Certificates) != 1 || len(b.Certificates[0].Certificate) == 0 {
				t.Errorf("%s: edit of one returned config's certificate reached the next", name)
			}
		}
		if !slices.Equal(f.steady.NextProtos, steadyALPN) || !slices.Equal(f.pairing.NextProtos, pairingALPN) {
			t.Fatalf("edit of a returned config reached the caller's config: steady %q pairing %q", f.steady.NextProtos, f.pairing.NextProtos)
		}
	})
}

// TestPinningConfigs_NeverAdvertisePair1 - no steady config offers pair1.
func TestPinningConfigs_NeverAdvertisePair1(t *testing.T) {
	key := matrixKey(t)
	pin := matrixPin(t, matrixKey(t))
	builds := map[string]func() (*tls.Config, error){
		"ClientDialTLS":               func() (*tls.Config, error) { return ClientDialTLS(key, pin) },
		"ClientListenTLS":             func() (*tls.Config, error) { return ClientListenTLS(key, pin) },
		"AgentListenTLS":              func() (*tls.Config, error) { return AgentListenTLS(key, []string{pin}) },
		"AgentDialTLS":                func() (*tls.Config, error) { return AgentDialTLS(key, []string{pin}) },
		"pinningTLS listen, empty ok": func() (*tls.Config, error) { return pinningTLS(key, modeListen, nil, true) },
		"pinningTLS dial, empty ok":   func() (*tls.Config, error) { return pinningTLS(key, modeDial, nil, true) },
		"pinningTLS listen, set":      func() (*tls.Config, error) { return pinningTLS(key, modeListen, []string{pin}, true) },
		"pinningTLS dial, set":        func() (*tls.Config, error) { return pinningTLS(key, modeDial, []string{pin}, true) },
	}
	for name, build := range builds {
		t.Run(name, func(t *testing.T) {
			cfg, err := build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if !slices.Equal(cfg.NextProtos, steadyALPN) {
				t.Errorf("NextProtos = %q, want exactly %q", cfg.NextProtos, steadyALPN)
			}
		})
	}

	f := newSeamFixture(t)
	t.Run("every steady-branch return", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			open bool
			h    *tls.ClientHelloInfo
		}{
			{"steady offered, open", true, hello(transport.ALPN)},
			{"steady offered, closed", false, hello(transport.ALPN)},
			{"no ALPN", true, hello()},
			{"unknown ALPN", true, hello("h3")},
			{"pair1, closed", false, hello(alpnPair1)},
			{"both, closed", false, hello(alpnPair1, transport.ALPN)},
		} {
			cfg, err := callSeam(t, pairingDispatcher(f.source(), f.pairing, always(tc.open)), tc.h)
			if err != nil || cfg == nil {
				t.Errorf("%s: cfg=%v err=%v", tc.name, cfg, err)
				continue
			}
			if !slices.Equal(cfg.NextProtos, steadyALPN) {
				t.Errorf("%s: NextProtos = %q, want exactly %q", tc.name, cfg.NextProtos, steadyALPN)
			}
		}
	})

	t.Run("steady source listing pair1 is rejected", func(t *testing.T) {
		bad := f.steady.Clone()
		bad.NextProtos = []string{transport.ALPN, alpnPair1}
		src := func() (*tls.Config, error) { return bad, nil }
		cfg, err := callSeam(t, pairingDispatcher(src, f.pairing, always(false)), hello(transport.ALPN))
		if cfg != nil || !errors.Is(err, errSeamBadSteady) {
			t.Errorf("cfg=%v err=%v, want nil and errSeamBadSteady", cfg, err)
		}
	})
}

// TestPairingDispatcher_IsTotal - never (nil,nil), never a
// non-pinning config, every reject a non-nil error.
//
// The steady config must be cloned before it is validated, so a source that
// hands out a shared pointer cannot change a config between its check and its
// use. That ordering is not observable from a deterministic test: the window
// lies inside one dispatcher call with no hook, and a concurrent mutator would
// be a data race whichever order is used. The post-condition is pinned here
// instead: every returned config is itself re-checked below.
func TestPairingDispatcher_IsTotal(t *testing.T) {
	f := newSeamFixture(t)
	errSource := errors.New("steady source failed")
	mutated := func(mut func(*tls.Config)) configSource {
		c := f.steady.Clone()
		mut(c)
		return func() (*tls.Config, error) { return c, nil }
	}
	const (
		wantSteady  = "steady"
		wantPairing = "pairing"
	)
	cases := []struct {
		name    string
		steady  configSource
		open    func() bool
		h       *tls.ClientHelloInfo
		want    string // wantSteady, wantPairing, or "" for reject
		wantErr error  // checked with errors.Is when want == ""
	}{
		{"nil hello", f.source(), always(true), nil, "", errSeamNoHello},
		{"nil SupportedProtos", f.source(), always(true), &tls.ClientHelloInfo{}, wantSteady, nil},
		{"empty SupportedProtos", f.source(), always(true), hello(), wantSteady, nil},
		{"unknown ALPN", f.source(), always(true), hello("h3"), wantSteady, nil},
		{"steady ALPN", f.source(), always(true), hello(transport.ALPN), wantSteady, nil},
		{"pair1, window closed", f.source(), always(false), hello(alpnPair1), wantSteady, nil},
		{"pair1, window open", f.source(), always(true), hello(alpnPair1), wantPairing, nil},
		{"both offered, open", f.source(), always(true), hello(transport.ALPN, alpnPair1), wantPairing, nil},
		{"both offered, closed", f.source(), always(false), hello(transport.ALPN, alpnPair1), wantSteady, nil},
		{"steady returns (nil,nil)", func() (*tls.Config, error) { return nil, nil }, always(false), hello(transport.ALPN), "", errSeamNilConfig},
		{"steady returns error", func() (*tls.Config, error) { return nil, errSource }, always(false), hello(transport.ALPN), "", errSource},
		{"steady panics", func() (*tls.Config, error) { panic("boom") }, always(false), hello(transport.ALPN), "", errSeamPanic},
		{"predicate panics", f.source(), func() bool { panic("boom") }, hello(alpnPair1), "", errSeamPanic},
		{"steady lacks VerifyPeerCertificate", mutated(func(c *tls.Config) { c.VerifyPeerCertificate = nil }), always(false), hello(transport.ALPN), "", errSeamBadSteady},
		{"steady lacks RequireAnyClientCert", mutated(func(c *tls.Config) { c.ClientAuth = tls.NoClientCert }), always(false), hello(transport.ALPN), "", errSeamBadSteady},
		{"steady has GetConfigForClient", mutated(func(c *tls.Config) {
			c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
		}), always(false), hello(transport.ALPN), "", errSeamBadSteady},
		{"steady has no certificate", mutated(func(c *tls.Config) { c.Certificates = nil }), always(false), hello(transport.ALPN), "", errSeamBadSteady},
		{"steady below TLS 1.3", mutated(func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }), always(false), hello(transport.ALPN), "", errSeamBadSteady},
		{"steady has GetCertificate", mutated(func(c *tls.Config) {
			c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &c.Certificates[0], nil }
		}), always(false), hello(transport.ALPN), "", errSeamBadSteady},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := callSeam(t, pairingDispatcher(tc.steady, f.pairing, tc.open), tc.h)
			if cfg == nil && err == nil {
				t.Fatal("dispatcher returned (nil, nil): fails open onto the outer config")
			}
			if cfg != nil && err != nil {
				t.Fatalf("dispatcher returned both a config and an error: %v", err)
			}
			if tc.want == "" {
				if cfg != nil {
					t.Fatalf("want reject, got config with NextProtos %q", cfg.NextProtos)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("err = %v, want errors.Is %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("want %s branch, got error %v", tc.want, err)
			}
			wantALPN := steadyALPN
			if tc.want == wantPairing {
				wantALPN = pairingALPN
			}
			if !slices.Equal(cfg.NextProtos, wantALPN) {
				t.Errorf("NextProtos = %q, want %q", cfg.NextProtos, wantALPN)
			}
			if cfg.ClientAuth != tls.RequireAnyClientCert || cfg.VerifyPeerCertificate == nil ||
				len(cfg.Certificates) != 1 || cfg.GetConfigForClient != nil || cfg.MinVersion < tls.VersionTLS13 {
				t.Errorf("returned config is not an authenticating pinning listener: %+v", cfg)
			}
		})
	}

	t.Run("predicate is consulted only when pair1 is offered", func(t *testing.T) {
		calls := 0
		open := func() bool { calls++; return true }
		cb := pairingDispatcher(f.source(), f.pairing, open)
		for _, h := range []*tls.ClientHelloInfo{hello(), hello("h3"), hello(transport.ALPN)} {
			callSeam(t, cb, h)
		}
		if calls != 0 {
			t.Errorf("pairingOpen called %d times without pair1 offered", calls)
		}
		callSeam(t, cb, hello(alpnPair1))
		if calls != 1 {
			t.Errorf("pairingOpen called %d times for one pair1 offer, want 1", calls)
		}
	})
}

// TestPairingDispatcher_EveryReturnedConfigDisablesTickets - no branch can resume a session.
func TestPairingDispatcher_EveryReturnedConfigDisablesTickets(t *testing.T) {
	f := newSeamFixture(t)
	steady := f.steady.Clone()
	steady.SessionTicketsDisabled = false
	pairing := f.pairing.Clone()
	pairing.SessionTicketsDisabled = false
	src := func() (*tls.Config, error) { return steady, nil }

	for _, tc := range []struct {
		name string
		open bool
		h    *tls.ClientHelloInfo
	}{
		{"steady", false, hello(transport.ALPN)},
		{"no ALPN", true, hello()},
		{"pair1 closed", false, hello(alpnPair1)},
		{"pair1 open", true, hello(alpnPair1)},
		{"both open", true, hello(alpnPair1, transport.ALPN)},
	} {
		t.Run("dispatcher/"+tc.name, func(t *testing.T) {
			cfg, err := callSeam(t, pairingDispatcher(src, pairing, always(tc.open)), tc.h)
			if err != nil || cfg == nil {
				t.Fatalf("cfg=%v err=%v", cfg, err)
			}
			if !cfg.SessionTicketsDisabled {
				t.Error("returned config has SessionTicketsDisabled=false: resumption would skip the pin check")
			}
			if cfg == steady || cfg == pairing {
				t.Error("returned the caller's config pointer, want a clone")
			}
			if steady.SessionTicketsDisabled || pairing.SessionTicketsDisabled {
				t.Error("dispatcher mutated the caller's config instead of a clone")
			}
		})
	}

	t.Run("outer config", func(t *testing.T) {
		outer, err := ListenTLSWithPairingConfig(src, pairing, always(true))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if !outer.SessionTicketsDisabled {
			t.Error("outer SessionTicketsDisabled = false")
		}
		if outer.GetConfigForClient == nil {
			t.Fatal("outer has no GetConfigForClient")
		}
		if !slices.Equal(outer.NextProtos, steadyALPN) {
			t.Errorf("outer NextProtos = %q, want %q", outer.NextProtos, steadyALPN)
		}
		if outer.MinVersion < tls.VersionTLS13 {
			t.Errorf("outer MinVersion = %x", outer.MinVersion)
		}
		if len(outer.Certificates) != 0 {
			t.Error("outer config carries certificates: a (nil,nil) return would authenticate with it")
		}
		for _, h := range []*tls.ClientHelloInfo{hello(transport.ALPN), hello(alpnPair1)} {
			cfg, err := callSeam(t, outer.GetConfigForClient, h)
			if err != nil || cfg == nil || !cfg.SessionTicketsDisabled || cfg.GetConfigForClient != nil {
				t.Errorf("outer callback for %q: cfg=%+v err=%v", h.SupportedProtos, cfg, err)
			}
		}
	})
}

// TestListenRoute_UsesNegotiatedProtocolOnly - routing reads the negotiated ALPN only.
func TestListenRoute_UsesNegotiatedProtocolOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		cs   tls.ConnectionState
		want listenRoute
	}{
		{"steady", tls.ConnectionState{NegotiatedProtocol: transport.ALPN}, routeSteady},
		{"pairing", tls.ConnectionState{NegotiatedProtocol: alpnPair1}, routePairing},
		{"empty", tls.ConnectionState{}, routeReject},
		{"unknown", tls.ConnectionState{NegotiatedProtocol: "h3"}, routeReject},
		{"ServerName pair1, ALPN steady", tls.ConnectionState{NegotiatedProtocol: transport.ALPN, ServerName: alpnPair1}, routeSteady},
		{"ServerName pair1, no ALPN", tls.ConnectionState{ServerName: alpnPair1, HandshakeComplete: true}, routeReject},
		{"ServerName steady, ALPN pair1", tls.ConnectionState{NegotiatedProtocol: alpnPair1, ServerName: transport.ALPN}, routePairing},
	} {
		if got := routeFor(tc.cs); got != tc.want {
			t.Errorf("%s: routeFor = %v, want %v", tc.name, got, tc.want)
		}
	}
	if routeReject == routeSteady || routeReject == routePairing || routeSteady == routePairing {
		t.Error("route values are not distinct")
	}
}

// TestPinningTLS_AllowEmptyAtStart - an empty pin set may be built on request
// but authorizes nobody.
func TestPinningTLS_AllowEmptyAtStart(t *testing.T) {
	f := newSeamFixture(t)
	key := matrixKey(t)
	for _, mode := range []transportMode{modeListen, modeDial} {
		cfg, err := pinningTLS(key, mode, nil, true)
		if err != nil {
			t.Fatalf("mode %d: allowEmptyAtStart + empty set must build: %v", mode, err)
		}
		if cfg.VerifyPeerCertificate == nil {
			t.Fatalf("mode %d: no pin callback", mode)
		}
		if err := cfg.VerifyPeerCertificate([][]byte{f.peerRaw}, nil); !errors.Is(err, ErrPinMismatch) {
			t.Errorf("mode %d: empty set accepted a valid cert: err=%v, want ErrPinMismatch", mode, err)
		}
		if _, err := pinningTLS(key, mode, nil, false); err == nil {
			t.Errorf("mode %d: empty set built without allowEmptyAtStart", mode)
		}
		if _, err := pinningTLS(key, mode, []string{}, false); err == nil {
			t.Errorf("mode %d: zero-length set built without allowEmptyAtStart", mode)
		}
		if _, err := pinningTLS(key, mode, []string{""}, true); err == nil {
			t.Errorf("mode %d: empty pin element accepted with allowEmptyAtStart", mode)
		}
	}
}

// TestListenTLSWithPairingConfig_RejectsInvalidInputs - build-time validation.
func TestListenTLSWithPairingConfig_RejectsInvalidInputs(t *testing.T) {
	f := newSeamFixture(t)
	if _, err := ListenTLSWithPairingConfig(f.source(), f.pairing, always(false)); err != nil {
		t.Fatalf("valid inputs rejected: %v", err)
	}
	mut := func(m func(*tls.Config)) *tls.Config {
		c := f.pairing.Clone()
		m(c)
		return c
	}
	for name, tc := range map[string]struct {
		steady  func() (*tls.Config, error)
		pairing *tls.Config
		open    func() bool
	}{
		"nil steady":                    {nil, f.pairing, always(false)},
		"nil pairing":                   {f.source(), nil, always(false)},
		"nil predicate":                 {f.source(), f.pairing, nil},
		"pairing without RequireAny":    {f.source(), mut(func(c *tls.Config) { c.ClientAuth = tls.RequestClientCert }), always(false)},
		"pairing without pin callback":  {f.source(), mut(func(c *tls.Config) { c.VerifyPeerCertificate = nil }), always(false)},
		"pairing without certificate":   {f.source(), mut(func(c *tls.Config) { c.Certificates = nil }), always(false)},
		"pairing with two certificates": {f.source(), mut(func(c *tls.Config) { c.Certificates = append(c.Certificates, c.Certificates[0]) }), always(false)},
		"pairing with GetConfigForClient": {f.source(), mut(func(c *tls.Config) {
			c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return c, nil }
		}), always(false)},
		"pairing with GetCertificate": {f.source(), mut(func(c *tls.Config) {
			c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &c.Certificates[0], nil }
		}), always(false)},
		"pairing below TLS 1.3":         {f.source(), mut(func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }), always(false)},
		"pairing with MinVersion unset": {f.source(), mut(func(c *tls.Config) { c.MinVersion = 0 }), always(false)},
	} {
		if cfg, err := ListenTLSWithPairingConfig(tc.steady, tc.pairing, tc.open); err == nil || cfg != nil {
			t.Errorf("%s: cfg=%v err=%v, want nil config and an error", name, cfg, err)
		}
	}
}
