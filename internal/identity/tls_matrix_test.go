package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
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

// ---- resumption vs. the pin callback ----------------------------------------
//
// @spec-handoff
//
// Interface: no exported signature changes. This observes handshake
// behavior of AgentListenTLS's and AgentDialTLS's returned *tls.Config over
// real loopback QUIC, using tls.ConnectionState.DidResume and a spy wrapping
// VerifyPeerCertificate.
//
// Behaviors covered:
//   - Two sequential handshakes against unmodified AgentListenTLS +
//     AgentDialTLS output: the second does not resume, and the listener's
//     VerifyPeerCertificate callback is invoked again on it.
//   - The same two-handshake sequence, with ClientSessionCache added to a
//     test-only copy of the dial config only (never to pinningTLS's
//     output), resumes on the second handshake — proving the harness can
//     detect resumption when it actually occurs.
//
// Edge cases: none beyond the two sequences above — this guards a config
// property, not input validation, so there is no third case to add.

// resumptionLoopbackUDP opens a UDP socket on loopback only, for one side of
// a handshake pair below. Binding "127.0.0.1" specifically, rather than a
// wildcard address, keeps these handshakes from ever being reachable off-host.
func resumptionLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// resumptionDial drives one client-side handshake to completion and returns
// the resulting connection's TLS state. The connection is deliberately left
// open (closed only via t.Cleanup) rather than closed as soon as Dial
// returns: the session ticket a listener sends is a post-handshake message
// delivered while the connection keeps processing traffic, so a caller that
// wants the client side to actually store it must keep the connection alive
// past the point Dial returns.
func resumptionDial(t *testing.T, tr *quic.Transport, addr net.Addr, cliConf *tls.Config) tls.ConnectionState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, cliConf, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	return conn.ConnectionState().TLS
}

// resumptionAccept accepts exactly one server-side connection. It is called
// once per handshake below rather than run as a long-lived accept loop, so
// each accept is paired with the one dial that produced it.
func resumptionAccept(t *testing.T, ln *quic.Listener) <-chan *quic.Conn {
	t.Helper()
	ch := make(chan *quic.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			close(ch)
			return
		}
		ch <- conn
	}()
	return ch
}

// TestTLSResumption pairs the property this package actually needs with a
// control that proves the property is checkable at all.
//
// crypto/tls documents that VerifyPeerCertificate does not run again on a
// resumed TLS 1.3 handshake: resumption trusts the certificate the first
// handshake already verified instead of re-invoking the callback. That
// callback is the only thing that authenticates a peer here, since chain
// verification is deliberately skipped, so a handshake that resumed would
// authenticate nobody on that connection. Nothing in this package makes that
// happen today — none of the four constructors sets ClientSessionCache, and
// a dial side with nowhere to store a session ticket cannot resume — but
// nothing stops a future edit (most plausibly someone reaching for
// ClientSessionCache for a latency win) from changing that.
//
// A single assertion that resumption does not occur cannot tell "the
// property holds" apart from "this harness cannot observe resumption at
// all" — both look identical from the outside. So the second subtest forces
// resumption through a config field that never appears on pinningTLS's
// output, and the first subtest's result is only meaningful because the
// second proves the harness would have caught it if it happened.
func TestTLSResumption(t *testing.T) {
	t.Run("production config does not resume, and reverifies every handshake", func(t *testing.T) {
		serverKey := matrixKey(t)
		clientKey := matrixKey(t)
		clientPin := matrixPin(t, clientKey)
		serverPin := matrixPin(t, serverKey)

		listenConf, err := AgentListenTLS(serverKey, []string{clientPin})
		if err != nil {
			t.Fatalf("AgentListenTLS: %v", err)
		}
		var verifyCalls atomic.Int32
		wrapped := listenConf.VerifyPeerCertificate
		listenConf.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			verifyCalls.Add(1)
			return wrapped(raw, chains)
		}

		dialConf, err := AgentDialTLS(clientKey, []string{serverPin})
		if err != nil {
			t.Fatalf("AgentDialTLS: %v", err)
		}

		serverUDP := resumptionLoopbackUDP(t)
		serverTr := &quic.Transport{Conn: serverUDP}
		t.Cleanup(func() { serverTr.Close() })
		ln, err := serverTr.Listen(listenConf, nil)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		clientUDP := resumptionLoopbackUDP(t)
		dialTr := &quic.Transport{Conn: clientUDP}
		t.Cleanup(func() { dialTr.Close() })

		accepted1 := resumptionAccept(t, ln)
		resumptionDial(t, dialTr, ln.Addr(), dialConf)
		if srv1, ok := <-accepted1; ok {
			t.Cleanup(func() { srv1.CloseWithError(0, "") })
		}
		if got := verifyCalls.Load(); got != 1 {
			t.Fatalf("verifyCalls after first handshake = %d, want 1", got)
		}

		accepted2 := resumptionAccept(t, ln)
		cs2 := resumptionDial(t, dialTr, ln.Addr(), dialConf)
		if srv2, ok := <-accepted2; ok {
			t.Cleanup(func() { srv2.CloseWithError(0, "") })
		}

		if cs2.DidResume {
			t.Fatal("second handshake resumed (DidResume=true): the shipped " +
				"config has never set ClientSessionCache, so nothing should " +
				"be available to resume from — something changed what the " +
				"dial side stores")
		}
		if got := verifyCalls.Load(); got != 2 {
			t.Fatalf("verifyCalls after second handshake = %d, want 2: "+
				"the pin callback did not run on the second connection", got)
		}
	})

	t.Run("control: resumption is observable given a test-only session cache", func(t *testing.T) {
		serverKey := matrixKey(t)
		clientKey := matrixKey(t)
		clientPin := matrixPin(t, clientKey)
		serverPin := matrixPin(t, serverKey)

		listenConf, err := AgentListenTLS(serverKey, []string{clientPin})
		if err != nil {
			t.Fatalf("AgentListenTLS: %v", err)
		}

		dialConf, err := AgentDialTLS(clientKey, []string{serverPin})
		if err != nil {
			t.Fatalf("AgentDialTLS: %v", err)
		}
		// TEST-ONLY: neither of these must ever appear on pinningTLS output.
		// pinningTLS now sets SessionTicketsDisabled unconditionally, so
		// both sides must clear it here to simulate the world this guard
		// closes off — otherwise the server never issues a ticket and the
		// client never stores one, and this subtest could no longer prove
		// the harness can observe resumption at all.
		listenConf.SessionTicketsDisabled = false
		dialConf.SessionTicketsDisabled = false
		dialConf.ClientSessionCache = tls.NewLRUClientSessionCache(1)

		serverUDP := resumptionLoopbackUDP(t)
		serverTr := &quic.Transport{Conn: serverUDP}
		t.Cleanup(func() { serverTr.Close() })
		ln, err := serverTr.Listen(listenConf, nil)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		clientUDP := resumptionLoopbackUDP(t)
		dialTr := &quic.Transport{Conn: clientUDP}
		t.Cleanup(func() { dialTr.Close() })

		accepted1 := resumptionAccept(t, ln)
		resumptionDial(t, dialTr, ln.Addr(), dialConf)
		if srv1, ok := <-accepted1; ok {
			t.Cleanup(func() { srv1.CloseWithError(0, "") })
		}

		accepted2 := resumptionAccept(t, ln)
		cs2 := resumptionDial(t, dialTr, ln.Addr(), dialConf)
		if srv2, ok := <-accepted2; ok {
			t.Cleanup(func() { srv2.CloseWithError(0, "") })
		}

		if !cs2.DidResume {
			t.Fatal("second handshake did not resume (DidResume=false) even " +
				"with a ClientSessionCache on the dial side: this harness " +
				"cannot demonstrate resumption, so the sibling subtest's " +
				"DidResume=false would prove nothing")
		}
	})
}
