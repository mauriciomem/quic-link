package identity

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// There are two independent axes here, and conflating them is what produces an
// unauthenticated listener. The TLS SHAPE follows who dials: a listener must
// request a peer certificate, a dialer must skip chain verification so its own
// callback is reached. The PIN SET follows the logical role: a client verifies
// the one server it expects, an agent verifies its authorized clients. Four
// combinations, and only two of them existed before reverse mode.

func matrixKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return key
}

func matrixPin(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	pin, err := PinForKey(key)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	return pin
}

// TestTLSMatrix_AllFourRows is the executable form of the design's matrix. A
// constructor whose shape silently drifts from its row is caught here first.
func TestTLSMatrix_AllFourRows(t *testing.T) {
	key := matrixKey(t)
	peer := matrixPin(t, matrixKey(t))

	tests := []struct {
		name           string
		build          func() (*tls.Config, error)
		wantClientAuth tls.ClientAuthType
		wantSkipVerify bool
	}{
		{
			name:           "client role, dials: no peer cert requested, chain check skipped",
			build:          func() (*tls.Config, error) { return ClientDialTLS(key, peer) },
			wantClientAuth: tls.NoClientCert,
			wantSkipVerify: true,
		},
		{
			name:           "agent role, listens: peer cert required",
			build:          func() (*tls.Config, error) { return AgentListenTLS(key, []string{peer}) },
			wantClientAuth: tls.RequireAnyClientCert,
			wantSkipVerify: false,
		},
		{
			name:           "client role, listens: peer cert required, single expected pin",
			build:          func() (*tls.Config, error) { return ClientListenTLS(key, peer) },
			wantClientAuth: tls.RequireAnyClientCert,
			wantSkipVerify: false,
		},
		{
			name:           "agent role, dials: no peer cert requested, authorized set",
			build:          func() (*tls.Config, error) { return AgentDialTLS(key, []string{peer}) },
			wantClientAuth: tls.NoClientCert,
			wantSkipVerify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := tt.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if got := cfg.ClientAuth; got != tt.wantClientAuth {
				t.Errorf("ClientAuth = %v, want %v", got, tt.wantClientAuth)
			}
			if got := cfg.InsecureSkipVerify; got != tt.wantSkipVerify {
				t.Errorf("InsecureSkipVerify = %v, want %v", got, tt.wantSkipVerify)
			}
			if cfg.VerifyPeerCertificate == nil {
				t.Error("VerifyPeerCertificate is nil: nothing would check the peer pin")
			}
			if len(cfg.Certificates) != 1 {
				t.Errorf("Certificates = %d, want 1: every role presents its own identity",
					len(cfg.Certificates))
			}
			if cfg.MinVersion != tls.VersionTLS13 {
				t.Errorf("MinVersion = %v, want TLS 1.3", cfg.MinVersion)
			}
		})
	}
}

// TestClientListenTLS_RequiresPeerCert is deliberately a single assertion
// against a hardcoded value, not one derived from anything else in this
// package. A listening endpoint that does not request a peer certificate never
// runs its pin callback at all, so it authenticates nobody while looking
// entirely correct. That is the one failure here that is silent.
func TestClientListenTLS_RequiresPeerCert(t *testing.T) {
	key := matrixKey(t)
	cfg, err := ClientListenTLS(key, matrixPin(t, matrixKey(t)))
	if err != nil {
		t.Fatalf("ClientListenTLS: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("ClientAuth = %v, want tls.RequireAnyClientCert — "+
			"without it no peer certificate is requested and the listener "+
			"authenticates nobody", cfg.ClientAuth)
	}
}

// TestListeningConfigs_RejectPeerWithNoCertificate is the functional companion
// to the assertion above: it drives a real TLS handshake from a peer that
// presents no certificate at all and requires it to fail. It catches a
// regression that keeps the struct field correct but changes when it is read.
func TestListeningConfigs_RejectPeerWithNoCertificate(t *testing.T) {
	serverKey := matrixKey(t)
	clientKey := matrixKey(t)
	clientPin := matrixPin(t, clientKey)

	tests := []struct {
		name  string
		build func() (*tls.Config, error)
	}{
		{
			name:  "client role listening",
			build: func() (*tls.Config, error) { return ClientListenTLS(serverKey, clientPin) },
		},
		{
			name:  "agent role listening",
			build: func() (*tls.Config, error) { return AgentListenTLS(serverKey, []string{clientPin}) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srvConf, err := tt.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			accepted := make(chan error, 1)
			go func() {
				conn, aerr := ln.Accept()
				if aerr != nil {
					accepted <- aerr
					return
				}
				defer conn.Close()
				tc := tls.Server(conn, srvConf)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				herr := tc.Handshake()
				if herr == nil {
					// Drain briefly so a wrongly-successful handshake is
					// observed as such rather than racing the close.
					_ = tc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					_, _ = io.CopyN(io.Discard, tc, 1)
				}
				accepted <- herr
			}()

			// A peer presenting NO certificate. Chain verification is skipped
			// so the only thing that can reject it is the listener requiring a
			// certificate in the first place.
			cliConf := &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // the listener's requirement is what is under test
				MinVersion:         tls.VersionTLS13,
			}
			cconn, err := tls.Dial("tcp", ln.Addr().String(), cliConf)
			if err == nil {
				_ = cconn.SetDeadline(time.Now().Add(2 * time.Second))
				// Force the handshake to complete both ways.
				_, _ = cconn.Write([]byte("x"))
				_ = cconn.Close()
			}

			srvErr := <-accepted
			if srvErr == nil {
				t.Fatal("handshake SUCCEEDED against a peer presenting no certificate: " +
					"the listener is authenticating nobody")
			}
		})
	}
}

// TestPinSets_FollowTheLogicalRole checks the other axis: each constructor
// accepts exactly the identity its role expects and rejects the other.
func TestPinSets_FollowTheLogicalRole(t *testing.T) {
	key := matrixKey(t)
	wantedKey := matrixKey(t)
	wanted := matrixPin(t, wantedKey)
	otherKey := matrixKey(t)

	wantedCert, err := SelfSignedCarrier(wantedKey)
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	otherCert, err := SelfSignedCarrier(otherKey)
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}

	builders := map[string]func() (*tls.Config, error){
		"client dials":   func() (*tls.Config, error) { return ClientDialTLS(key, wanted) },
		"client listens": func() (*tls.Config, error) { return ClientListenTLS(key, wanted) },
		"agent listens":  func() (*tls.Config, error) { return AgentListenTLS(key, []string{wanted}) },
		"agent dials":    func() (*tls.Config, error) { return AgentDialTLS(key, []string{wanted}) },
	}

	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			cfg, err := build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if err := cfg.VerifyPeerCertificate(wantedCert.Certificate, nil); err != nil {
				t.Errorf("expected peer rejected: %v", err)
			}
			err = cfg.VerifyPeerCertificate(otherCert.Certificate, nil)
			if !errors.Is(err, ErrPinMismatch) {
				t.Errorf("unexpected peer: err = %v, want ErrPinMismatch", err)
			}
			if err := cfg.VerifyPeerCertificate(nil, nil); !errors.Is(err, ErrNoPeerCert) {
				t.Errorf("empty chain: err = %v, want ErrNoPeerCert", err)
			}
		})
	}
}

// TestConstructors_RejectEmptyPinSets keeps every path authenticated: a
// constructor with nothing to verify against must fail loudly at construction
// rather than produce a config that accepts anyone.
func TestConstructors_RejectEmptyPinSets(t *testing.T) {
	key := matrixKey(t)
	cases := map[string]func() (*tls.Config, error){
		"client dials, empty pin":   func() (*tls.Config, error) { return ClientDialTLS(key, "") },
		"client listens, empty pin": func() (*tls.Config, error) { return ClientListenTLS(key, "") },
		"agent listens, empty set":  func() (*tls.Config, error) { return AgentListenTLS(key, nil) },
		"agent dials, empty set":    func() (*tls.Config, error) { return AgentDialTLS(key, nil) },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); err == nil {
				t.Error("constructor accepted an empty pin set: this would authenticate nobody")
			}
		})
	}
}
