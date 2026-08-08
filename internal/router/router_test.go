package router

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/mauriciomem/quic-link/internal/identity"
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

// TestNewRejectsBadRouteName verifies that New validates every route name
// through ValidateRouteName as defense in depth, even though the flag and
// config call sites are expected to catch a bad name first. The error must
// not be silently accepted here: a name that would be rejected everywhere
// else must not slip through router construction.
func TestNewRejectsBadRouteName(t *testing.T) {
	_, err := New(map[string]string{"pg:app": "tcp://127.0.0.1:5432"}, nil)
	if err == nil {
		t.Fatal("New with an invalid route name: want error, got nil")
	}
}

// TestNew_OverrideWinsOverBuiltin proves that an override for a built-in
// route name ("ssh") actually takes effect: Dial must reach the overridden
// address, not the tcp://127.0.0.1:22 built-in default. It also pins the
// decided provenance semantics: Builtin tracks whether the operator supplied
// the entry, not whether its name happens to be one of the two reserved
// names. An override for "ssh" must therefore report Builtin: false, and the
// untouched "docker" default must report Builtin: true.
func TestNew_OverrideWinsOverBuiltin(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "override.sock")
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

	r, err := New(map[string]string{"ssh": "unix://" + sockPath}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := r.Dial(context.Background(), Identity{}, proto.Header{Kind: proto.KindTCP, Target: "ssh"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("override wins")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q — the built-in tcp://127.0.0.1:22 ssh route was used instead of the override", got, msg)
	}

	details := r.RouteDetails()
	byName := make(map[string]RouteDetail, len(details))
	for _, d := range details {
		byName[d.Name] = d
	}
	sshDetail, ok := byName["ssh"]
	if !ok {
		t.Fatal("RouteDetails() has no entry for \"ssh\"")
	}
	if sshDetail.Builtin {
		t.Errorf(`RouteDetails()["ssh"].Builtin = true, want false — the operator overrode the built-in address, so provenance must say "not a default" regardless of the name being one of the two reserved ones`)
	}
	if sshDetail.Address != "unix://"+sockPath {
		t.Errorf("RouteDetails()[\"ssh\"].Address = %q, want %q", sshDetail.Address, "unix://"+sockPath)
	}
	dockerDetail, ok := byName["docker"]
	if !ok {
		t.Fatal("RouteDetails() has no entry for \"docker\"")
	}
	if !dockerDetail.Builtin {
		t.Errorf(`RouteDetails()["docker"].Builtin = false, want true — nothing overrode it, so it must still trace back to the compiled-in default`)
	}
}

// TestRouteDetails_Provenance covers the full provenance matrix beyond the
// single override TestNew_OverrideWinsOverBuiltin exercises: an entry that is
// neither of the two reserved names at all must also report Builtin: false,
// since Builtin answers "did the operator configure this" rather than "is
// this name one of the two special ones".
func TestRouteDetails_Provenance(t *testing.T) {
	r, err := New(map[string]string{
		"ssh":    "tcp://10.0.0.1:2222",  // overrides a built-in name
		"custom": "tcp://127.0.0.1:9000", // a name that was never a default
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := map[string]Provenance{
		// Overriding a compiled-in name is still an operator's doing, so it
		// reports config provenance rather than builtin.
		"ssh":    ProvenanceConfig,
		"docker": ProvenanceBuiltin,
		"custom": ProvenanceConfig,
	}
	details := r.RouteDetails()
	if len(details) != len(want) {
		t.Fatalf("RouteDetails() returned %d entries, want %d", len(details), len(want))
	}
	for _, d := range details {
		wantProv, ok := want[d.Name]
		if !ok {
			t.Fatalf("RouteDetails() returned unexpected entry %q", d.Name)
		}
		if d.Provenance != wantProv {
			t.Errorf("RouteDetails()[%q].Provenance = %q, want %q", d.Name, d.Provenance, wantProv)
		}
		if wantBuiltin := wantProv == ProvenanceBuiltin; d.Builtin != wantBuiltin {
			t.Errorf("RouteDetails()[%q].Builtin = %v, want %v", d.Name, d.Builtin, wantBuiltin)
		}
	}
}

// TestRouteDetail_BuiltinIsDerivedFromProvenance is the load-bearing test for
// the two-field shape. Builtin is kept only because other programs already
// read it, and it is computed from Provenance rather than stored a second
// time — so the one thing that must never happen is the two fields
// disagreeing. Asserting the derivation over every entry, in a table that
// covers all three provenances, is what makes that a checked property rather
// than a promise in a comment.
//
// It deliberately does not hard-code which names are builtin: it asserts the
// relationship between the two fields, so it keeps protecting the invariant
// even if the set of compiled-in defaults changes.
func TestRouteDetail_BuiltinIsDerivedFromProvenance(t *testing.T) {
	r, err := New(map[string]string{
		"ssh":    "tcp://10.0.0.1:2222",
		"custom": "tcp://127.0.0.1:9000",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A runtime entry is written directly, because no mutator exists yet at
	// this point in the tree: the invariant has to hold for the third state
	// before the code that creates it arrives, or the first mutation ships
	// against an unproven shape.
	r.mu.Lock()
	r.routes["dynamic"] = route{
		raw: "tcp://127.0.0.1:7000", network: "tcp", address: "127.0.0.1:7000",
		prov: ProvenanceRuntime,
	}
	r.mu.Unlock()

	seen := map[Provenance]bool{}
	for _, d := range r.RouteDetails() {
		seen[d.Provenance] = true
		if want := d.Provenance == ProvenanceBuiltin; d.Builtin != want {
			t.Errorf("entry %q: Builtin = %v but Provenance = %q; the two must never disagree",
				d.Name, d.Builtin, d.Provenance)
		}
		if d.Provenance == "" {
			t.Errorf("entry %q reports an empty provenance; every entry must say where it came from", d.Name)
		}
	}
	for _, p := range []Provenance{ProvenanceBuiltin, ProvenanceConfig, ProvenanceRuntime} {
		if !seen[p] {
			t.Errorf("no entry with provenance %q was exercised; the invariant is unproven for that state", p)
		}
	}
}

// TestRouteDetails_SortedStable proves RouteDetails returns its entries
// sorted by name, and that repeated calls against the same Router produce the
// identical order every time. Six entries (rather than two or three) are used
// deliberately: a small map can appear to iterate in a stable order by
// accident, which would let a broken (unsorted) implementation pass a weaker
// version of this test for the wrong reason.
func TestRouteDetails_SortedStable(t *testing.T) {
	r, err := New(map[string]string{
		"zzz-custom": "tcp://127.0.0.1:9001",
		"aaa-custom": "tcp://127.0.0.1:9002",
		"mmm-custom": "tcp://127.0.0.1:9003",
		"bbb-custom": "tcp://127.0.0.1:9004",
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := []string{"aaa-custom", "bbb-custom", "docker", "mmm-custom", "ssh", "zzz-custom"}

	for attempt := 0; attempt < 2; attempt++ {
		details := r.RouteDetails()
		got := make([]string, len(details))
		for i, d := range details {
			got[i] = d.Name
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("RouteDetails() order (call #%d) = %v, want %v", attempt+1, got, want)
		}
	}
}

// TestRouteDetails_ConcurrentWriter exercises Targets, RouteDetails, and
// Dial's resolve() under -race against a goroutine that mutates the routes
// map directly, holding the Router's own mutex. There is no AddRoute today
// — the route table is built once at construction and never written again,
// so this writer is not a real code path. It exists only to prove every
// reader's lock is real, resolve() included: a reader that forgot to take
// it would race against this writer under -race even though it never races
// against anything the project actually ships yet.
func TestRouteDetails_ConcurrentWriter(t *testing.T) {
	r, err := New(map[string]string{"custom": "tcp://127.0.0.1:9000"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			r.mu.Lock()
			name := fmt.Sprintf("dynamic%d", i)
			r.routes[name] = route{
				raw: "tcp://127.0.0.1:1", network: "tcp", address: "127.0.0.1:1",
				prov: ProvenanceRuntime,
			}
			i++
			r.mu.Unlock()
		}
	}()

	ctx := context.Background()
	for i := 0; i < 200; i++ {
		_ = r.Targets()
		_ = r.RouteDetails()
		// The dial itself is expected to fail — nothing listens on
		// 127.0.0.1:9000 — that is fine: only the map read inside
		// resolve() is under test here, not the outcome of the dial.
		_, _ = r.Dial(ctx, Identity{}, proto.Header{Kind: proto.KindTCP, Target: "custom"})
	}
	close(stop)
	wg.Wait()
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
	// The router pin MUST equal identity.Pin over the same SPKI — one formula
	// (single source of truth).
	if want := identity.Pin(cert.RawSubjectPublicKeyInfo); id1.Pin != want {
		t.Fatalf("router pin %q != identity.Pin %q", id1.Pin, want)
	}
	if len(id1.Short()) != 8 {
		t.Fatalf("Short() = %q, want 8 chars", id1.Short())
	}
	if _, err := IdentityFromCerts(nil); err == nil {
		t.Fatal("want error for empty cert chain")
	}
}
