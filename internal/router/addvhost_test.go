package router

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/mauriciomem/quic-link/internal/proto"
)

// TestAddVhost_ConcurrentWithLiveLookups is the reason this table needed a
// lock at all. It publishes names while requests arrive by name, which is the
// pairing that happens for real the moment anyone publishes a name on a busy
// agent.
//
// Without synchronization this does not merely return a wrong answer: reading
// a Go map while another goroutine writes it stops the process, mid-request,
// with nothing recoverable. So this test was written and watched to FAIL under
// -race before the lock existed, rather than added afterwards to accompany it —
// a test that has only ever passed proves the lock is present, not that it was
// ever needed.
func TestAddVhost_ConcurrentWithLiveLookups(t *testing.T) {
	r, err := NewWithVhosts(nil, map[string]string{"seed.server1.internal": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Readers: the data-plane lookup and the listing used for diagnosis, both
	// of which read the same maps a publisher writes.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// The dial is expected to fail, nothing is listening; only the
				// table read on the way there is under test.
				_, _ = r.Dial(ctx, Identity{}, proto.Header{
					Kind: proto.KindHTTP, Host: "seed.server1.internal",
				})
				_ = r.Vhosts()
			}
		}()
	}

	// The table is bounded, so the writer cannot simply grow it four hundred
	// times. What this test needs is a stream of writes running against live
	// readers, not a large table — so once the table is nearly full each new
	// name is taken back straight after it is published. Every name is still
	// distinct, so no write is turned into the repeat case, which does not
	// touch the map at all and would quietly stop exercising anything.
	for i := 0; i < 400; i++ {
		host := fmt.Sprintf("svc%d.server1.internal", i)
		if err := r.AddVhost(host, 3000+i%100); err != nil {
			t.Fatalf("AddVhost(%d): %v", i, err)
		}
		if i < MaxVhosts-2 {
			continue
		}
		if _, err := r.RemoveVhost(host); err != nil {
			t.Fatalf("RemoveVhost(%d): %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestAddVhost_RepeatingTheSameRequestSucceeds covers the retry a user will
// actually perform. Publishing a name is not something that can be undone yet,
// so a second identical request had to be either harmless or a dead end; it is
// harmless. The table must be unchanged afterwards, not merely un-erroring.
func TestAddVhost_RepeatingTheSameRequestSucceeds(t *testing.T) {
	r := mustVhostRouter(t)
	if err := r.AddVhost("grafana.server1.internal", 3000); err != nil {
		t.Fatalf("first AddVhost: %v", err)
	}
	before := r.Vhosts()
	if err := r.AddVhost("grafana.server1.internal", 3000); err != nil {
		t.Fatalf("repeating the identical request was refused: %v", err)
	}
	if got, want := len(r.Vhosts()), len(before); got != want {
		t.Errorf("the table grew from %d to %d entries on a repeated request", want, got)
	}
	assertVhostAddress(t, r, "grafana.server1.internal", "tcp://127.0.0.1:3000")
}

// TestAddVhost_SameNameDifferentPortIsRefused draws the line the previous test
// does not: a repeat is only harmless when it asks for what is already true.
// Asking for the same name at a different place is a takeover attempt, whether
// or not it was meant as one, and it is refused with the existing entry intact.
func TestAddVhost_SameNameDifferentPortIsRefused(t *testing.T) {
	r := mustVhostRouter(t)
	if err := r.AddVhost("grafana.server1.internal", 3000); err != nil {
		t.Fatalf("first AddVhost: %v", err)
	}
	err := r.AddVhost("grafana.server1.internal", 9999)
	if !errors.Is(err, ErrVhostExists) {
		t.Fatalf("re-pointing a published name returned %v, want ErrVhostExists", err)
	}
	// The point of the refusal is that the original survives it.
	assertVhostAddress(t, r, "grafana.server1.internal", "tcp://127.0.0.1:3000")
}

// TestAddVhost_RefusesToDisplaceAConfiguredName is the safety rule that
// matters most here. An operator's configured name must not be reassignable by
// a caller, and the refusal has to say that is why, because "already exists"
// alone would leave the operator unsure whether they collided with themselves
// or were prevented from doing something.
func TestAddVhost_RefusesToDisplaceAConfiguredName(t *testing.T) {
	r, err := NewWithVhosts(nil, map[string]string{
		"grafana.server1.internal": "tcp://127.0.0.1:3000",
	}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	addErr := r.AddVhost("grafana.server1.internal", 9999)
	if !errors.Is(addErr, ErrVhostExists) {
		t.Fatalf("displacing a configured name returned %v, want ErrVhostExists", addErr)
	}
	if !strings.Contains(addErr.Error(), "configuration") {
		t.Errorf("the refusal does not say the entry came from configuration: %v", addErr)
	}
	assertVhostAddress(t, r, "grafana.server1.internal", "tcp://127.0.0.1:3000")
}

// TestAddVhost_ConfiguredNameIsRefusedEvenWhenItMatches closes the gap the
// obvious version of the retry rule leaves open. Letting a repeat through
// because "it asks for what is already there" is only safe if the entry was
// also published the same way; comparing addresses alone means an operator's
// configured name is silently adopted by whichever caller happens to name the
// same port, and that entry then looks like something a caller may later take
// away.
//
// The situation is not far-fetched: a caller publishing the service the
// operator already configured, on the port it already uses, is the most likely
// collision there is, not the least.
//
// This is the test that a mutation of the retry rule has to fail. Without it,
// dropping the origin check passes the whole suite.
func TestAddVhost_ConfiguredNameIsRefusedEvenWhenItMatches(t *testing.T) {
	const host = "grafana.server1.internal"
	r, err := NewWithVhosts(nil, map[string]string{host: "tcp://127.0.0.1:3000"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	// Deliberately the SAME port the operator configured.
	addErr := r.AddVhost(host, 3000)
	if !errors.Is(addErr, ErrVhostExists) {
		t.Fatalf("publishing over a configured name with a matching port returned %v, "+
			"want ErrVhostExists — a caller must not adopt an operator's entry by matching it", addErr)
	}
	if !strings.Contains(addErr.Error(), "configuration") {
		t.Errorf("the refusal does not say the entry came from configuration: %v", addErr)
	}

	// The entry must still be the operator's, not one that now looks
	// caller-published and therefore removable later.
	rt, ok := r.resolve(proto.Header{Kind: proto.KindHTTP, Host: host})
	if !ok {
		t.Fatal("the configured name stopped resolving")
	}
	if rt.prov != ProvenanceConfig {
		t.Errorf("the configured entry now reports provenance %q, want %q", rt.prov, ProvenanceConfig)
	}
}

// TestAddVhost_RejectsWhatCannotBePublished walks the request checks. Each case
// is refused before anything is stored, which the final assertion checks
// directly rather than inferring from the error: a table left holding a
// half-made entry is the failure this ordering exists to prevent.
func TestAddVhost_RejectsWhatCannotBePublished(t *testing.T) {
	cases := []struct {
		name string
		host string
		port int
		why  string
	}{
		{"a wildcard", "*.server1.internal", 3000, "claims names nobody has claimed"},
		{"a bare star", "*", 3000, "claims everything"},
		{"uppercase", "Grafana.server1.internal", 3000, "is not how a hostname is compared"},
		{"a trailing dot", "grafana.server1.internal.", 3000, "has an empty last label"},
		{"a port suffix in the name", "grafana.server1.internal:8080", 3000, "is not a hostname"},
		{"an empty name", "", 3000, "is not a name"},
		{"port zero", "grafana.server1.internal", 0, "is not a port and nothing here picks one"},
		{"a negative port", "grafana.server1.internal", -1, "is not a port"},
		{"a port above the range", "grafana.server1.internal", 65536, "is outside the usable range"},
		{"a wildly out-of-range port", "grafana.server1.internal", 99999, "would parse as an address and fail much later"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustVhostRouter(t)
			err := r.AddVhost(c.host, c.port)
			if !errors.Is(err, ErrVhostRejected) {
				t.Fatalf("AddVhost(%q, %d) returned %v, want ErrVhostRejected (%s)", c.host, c.port, err, c.why)
			}
			if got := r.Vhosts(); len(got) != 0 {
				t.Errorf("a refused request still changed the table: %v", got)
			}
		})
	}
}

// TestAddVhost_PublishedNameResolvesAndReportsItsOrigin proves the entry is
// actually usable afterwards and is recorded as having been published at
// runtime — the distinction removal safety will depend on.
func TestAddVhost_PublishedNameResolvesAndReportsItsOrigin(t *testing.T) {
	r := mustVhostRouter(t)
	if err := r.AddVhost("grafana.server1.internal", 3000); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	rt, ok := r.resolve(proto.Header{Kind: proto.KindHTTP, Host: "grafana.server1.internal"})
	if !ok {
		t.Fatal("a published name does not resolve")
	}
	if rt.address != "127.0.0.1:3000" {
		t.Errorf("published name resolves to %q, want the loopback address for the port given", rt.address)
	}
	if rt.prov != ProvenanceRuntime {
		t.Errorf("published entry reports provenance %q, want %q", rt.prov, ProvenanceRuntime)
	}
}

func mustVhostRouter(t *testing.T) *Router {
	t.Helper()
	r, err := NewWithVhosts(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	return r
}

func assertVhostAddress(t *testing.T, r *Router, host, wantRaw string) {
	t.Helper()
	rt, ok := r.resolve(proto.Header{Kind: proto.KindHTTP, Host: host})
	if !ok {
		t.Fatalf("%q does not resolve", host)
	}
	if rt.raw != wantRaw {
		t.Errorf("%q points at %q, want %q", host, rt.raw, wantRaw)
	}
}
