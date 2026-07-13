package router

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"testing"

	"github.com/mauriciomem/quic-link/internal/proto"
)

func TestParseAddr(t *testing.T) {
	cases := []struct {
		name                     string
		raw                      string
		wantNetwork, wantAddress string
		wantErr                  bool
	}{
		{"tcp ok", "tcp://127.0.0.1:22", "tcp", "127.0.0.1:22", false},
		{"unix ok", "unix:///var/run/docker.sock", "unix", "/var/run/docker.sock", false},
		{"unix relative", "unix://relative/path", "", "", true},
		{"no scheme", "127.0.0.1:22", "", "", true},
		{"tcp no port", "tcp://127.0.0.1", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			network, address, err := parseAddr(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAddr(%q): want error, got nil", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAddr(%q): %v", tc.raw, err)
			}
			if network != tc.wantNetwork || address != tc.wantAddress {
				t.Fatalf("parseAddr(%q) = (%q,%q), want (%q,%q)",
					tc.raw, network, address, tc.wantNetwork, tc.wantAddress)
			}
		})
	}
}

func TestDialUnknownTarget(t *testing.T) {
	r, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.Dial(context.Background(), Identity{}, proto.Header{Kind: proto.KindTCP, Target: "nope"})
	if !errors.Is(err, ErrUnknownTarget) {
		t.Fatalf("got %v, want ErrUnknownTarget", err)
	}
}

func TestDialUnauthorized(t *testing.T) {
	deny := PolicyFunc(func(Identity, proto.Header) error { return errors.New("denied") })
	r, err := New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, deny)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.Dial(context.Background(), Identity{Pin: "x"}, proto.Header{Kind: proto.KindTCP, Target: "ssh"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("got %v, want ErrUnauthorized", err)
	}
}

func TestDialUnixRoundTrip(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "x.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c) //nolint:errcheck
		}
	}()

	r, err := New(map[string]string{"docker": "unix://" + sockPath}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := r.Dial(context.Background(), Identity{}, proto.Header{Kind: proto.KindTCP, Target: "docker"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello unix")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

func TestIdentityFromCerts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	id1, err := IdentityFromCerts([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("IdentityFromCerts: %v", err)
	}
	id2, _ := IdentityFromCerts([]*x509.Certificate{cert})
	if id1.Pin == "" || id1.Pin != id2.Pin {
		t.Fatalf("pin not stable: %q vs %q", id1.Pin, id2.Pin)
	}
	if len(id1.Short()) != 8 {
		t.Fatalf("Short() = %q, want 8 chars", id1.Short())
	}
	if _, err := IdentityFromCerts(nil); err == nil {
		t.Fatal("want error for empty cert chain")
	}
}
