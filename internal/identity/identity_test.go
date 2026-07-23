package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPinEquality asserts the critical invariant: for one key, the pin
// computed from its public key, from a carrier certificate over it, and from
// keygen's PinForKey are all identical. This is what makes "keygen prints pin X"
// and "peer computed pin X from the carrier" the same value.
func TestPinEquality(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	pinPub, err := PinFromPublic(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("PinFromPublic: %v", err)
	}
	pinKey, err := PinForKey(key)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	carrier, err := SelfSignedCarrier(key)
	if err != nil {
		t.Fatalf("SelfSignedCarrier: %v", err)
	}
	pinCarrier := PinFromCert(carrier.Leaf)

	if pinPub != pinKey || pinPub != pinCarrier {
		t.Fatalf("pins disagree: public=%q key=%q carrier=%q", pinPub, pinKey, pinCarrier)
	}

	// The carrier SPKI must be byte-identical to the marshalled public key.
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if Pin(spki) != pinCarrier {
		t.Fatalf("SPKI pin %q != carrier pin %q", Pin(spki), pinCarrier)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := WriteKey(path, key); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key mode = %o, want 0600", perm)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !key.Equal(loaded) {
		t.Fatal("loaded key does not equal written key")
	}
}

func TestLoadKeyRejectsNonEd25519(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rsa.pem")

	// Marshal a valid PKCS#8 key that is NOT Ed25519 (an ECDSA key) and confirm
	// LoadKey rejects it.
	ecPKCS8 := mustNonEd25519PKCS8(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPKCS8})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write rsa key: %v", err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("LoadKey accepted a non-Ed25519 key")
	}
}

func TestParsePin(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	good, err := PinForKey(key)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}

	if got, err := ParsePin("  " + good + "\n"); err != nil || got != good {
		t.Fatalf("ParsePin(padded) = (%q,%v), want (%q,nil)", got, err, good)
	}
	for _, bad := range []string{"", "   ", "not-base64!!!", "YWJj"} { // "abc" -> 3 bytes
		if _, err := ParsePin(bad); err == nil {
			t.Fatalf("ParsePin(%q): want error, got nil", bad)
		}
	}

	// A non-canonical base64 spelling (trailing bits set) of a valid 32-byte
	// digest must normalize to the canonical pin, so it still matches the pin
	// computed during the handshake.
	zeros := make([]byte, 32)
	canonical := base64.StdEncoding.EncodeToString(zeros)
	nonCanonical := canonical[:len(canonical)-2] + "B" + canonical[len(canonical)-1:]
	if nonCanonical == canonical {
		t.Fatal("test setup: non-canonical variant equals canonical")
	}
	got, err := ParsePin(nonCanonical)
	if err != nil {
		t.Fatalf("ParsePin(non-canonical): %v", err)
	}
	if got != canonical {
		t.Fatalf("ParsePin did not canonicalize: %q -> %q, want %q", nonCanonical, got, canonical)
	}
}

// TestPinningHandshake verifies at the TLS layer (over a loopback TCP
// connection) that a mutual pinning handshake succeeds iff both sides' pins
// match, and that a mismatch on either side aborts the handshake.
func TestPinningHandshake(t *testing.T) {
	serverKey, err := Generate()
	if err != nil {
		t.Fatalf("server Generate: %v", err)
	}
	clientKey, err := Generate()
	if err != nil {
		t.Fatalf("client Generate: %v", err)
	}
	serverPin, _ := PinForKey(serverKey)
	clientPin, _ := PinForKey(clientKey)
	wrongPin, _ := PinForKey(mustKey(t))

	cases := []struct {
		name            string
		authorized      []string
		expectServerPin string
		wantErr         bool
	}{
		{"match", []string{clientPin}, serverPin, false},
		{"client not authorized", []string{wrongPin}, serverPin, true},
		{"wrong server pin", []string{clientPin}, wrongPin, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverTLS, err := ServerTLS(serverKey, tc.authorized)
			if err != nil {
				t.Fatalf("ServerTLS: %v", err)
			}
			clientTLS, err := ClientTLS(clientKey, tc.expectServerPin)
			if err != nil {
				t.Fatalf("ClientTLS: %v", err)
			}

			c := clientTLS
			s := serverTLS

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			srvErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					srvErr <- err
					return
				}
				srv := tls.Server(conn, s)
				e := srv.Handshake()
				conn.Close()
				srvErr <- e
			}()

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			cli := tls.Client(raw, c)
			cerr := cli.Handshake()
			raw.Close()

			var serr error
			select {
			case serr = <-srvErr:
			case <-time.After(5 * time.Second):
				t.Fatal("server handshake did not return")
			}

			handshakeErr := cerr != nil || serr != nil
			if handshakeErr != tc.wantErr {
				t.Fatalf("handshake err = %v (client=%v server=%v), want err=%v",
					handshakeErr, cerr, serr, tc.wantErr)
			}
		})
	}
}

func TestServerTLSRejectsEmptyAuthorized(t *testing.T) {
	key := mustKey(t)
	if _, err := ServerTLS(key, nil); err == nil {
		t.Fatal("ServerTLS accepted an empty authorized set")
	}
}

func TestVerifyPinRejectsEmptyChain(t *testing.T) {
	cb := verifyPin(map[string]struct{}{"x": {}})
	if err := cb(nil, nil); !errors.Is(err, ErrNoPeerCert) {
		t.Fatalf("empty chain: got %v, want ErrNoPeerCert", err)
	}
}

// TestReadMetaRoundTrip verifies that ReadMeta correctly parses what WriteMeta
// writes, and returns the same UTC time to second precision.
func TestReadMetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	// WriteMeta truncates to second precision (RFC3339), so we do the same.
	now := time.Now().UTC().Truncate(time.Second)

	if err := WriteMeta(keyPath, now); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}

	got, present, err := ReadMeta(keyPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if !present {
		t.Fatal("ReadMeta: present = false, want true")
	}
	if !got.Equal(now) {
		t.Errorf("ReadMeta time = %v, want %v", got, now)
	}
}

// TestReadMetaAbsent verifies that ReadMeta returns present=false and nil
// error when the sidecar file does not exist.
func TestReadMetaAbsent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	// No WriteMeta call — the .meta file does not exist.

	_, present, err := ReadMeta(keyPath)
	if err != nil {
		t.Fatalf("ReadMeta for absent file: %v", err)
	}
	if present {
		t.Fatal("ReadMeta: present = true for absent file, want false")
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return k
}

// mustNonEd25519PKCS8 returns a PKCS#8-encoded ECDSA key (a valid PKCS#8 key
// that is deliberately not Ed25519).
func mustNonEd25519PKCS8(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return der
}
