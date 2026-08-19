package router_test

// A published name was reported by nothing until these existed. What matters
// most in the answer is where each name came from, because that is the only
// thing distinguishing one an operator configured from one a caller added while
// the agent was running.

import (
	"fmt"
	"testing"

	"github.com/mauriciomem/quic-link/internal/router"
)

func TestVhostDetailsReportsWhereEachNameCameFrom(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{
		"cfg.s.internal":    "tcp://127.0.0.1:3000",
		"*.wild.s.internal": "tcp://127.0.0.1:3001",
	}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	if err := r.AddVhost("rt.s.internal", 4000); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	got := r.VhostDetails()
	if len(got) != 3 {
		t.Fatalf("got %d names, want 3: %+v", len(got), got)
	}

	// Sorted, so the answer does not depend on map ordering.
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Errorf("names are not sorted: %q before %q", got[i-1].Name, got[i].Name)
		}
	}

	by := map[string]router.VhostDetail{}
	for _, d := range got {
		by[d.Name] = d
	}

	cfg, ok := by["cfg.s.internal"]
	if !ok {
		t.Fatalf("the configured name is missing: %+v", got)
	}
	if cfg.Provenance != router.ProvenanceConfig {
		t.Errorf("a configured name reports provenance %q, want %q", cfg.Provenance, router.ProvenanceConfig)
	}
	if cfg.Address != "tcp://127.0.0.1:3000" {
		t.Errorf("a configured name reports address %q, want the address it was configured with", cfg.Address)
	}

	rt, ok := by["rt.s.internal"]
	if !ok {
		t.Fatalf("the name published while running is missing: %+v", got)
	}
	if rt.Provenance != router.ProvenanceRuntime {
		t.Errorf("a name published while running reports provenance %q, want %q",
			rt.Provenance, router.ProvenanceRuntime)
	}

	// A pattern is reported with the star it was written with, because that is
	// the name an operator will look for.
	if _, ok := by["*.wild.s.internal"]; !ok {
		t.Errorf("a pattern name is not reported with its star: %+v", got)
	}
}

// TestVhostDetailsBuiltinAgreesWithProvenance mirrors the same rule the route
// listing follows. No published name is compiled in, so this must be false
// throughout — a true here would mean something invented a provenance the
// hostname table cannot produce.
func TestVhostDetailsBuiltinAgreesWithProvenance(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"cfg.s.internal": "tcp://127.0.0.1:3000"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	if err := r.AddVhost("rt.s.internal", 4000); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	for _, d := range r.VhostDetails() {
		if d.Builtin != (d.Provenance == router.ProvenanceBuiltin) {
			t.Errorf("%s: builtin=%v disagrees with provenance %q", d.Name, d.Builtin, d.Provenance)
		}
		if d.Builtin {
			t.Errorf("%s reports itself as compiled in, which no published name is", d.Name)
		}
	}
}

// TestVhostDetailsOnARouterWithNoNames covers the honest empty answer: an agent
// publishing nothing is a valid configuration, not a failure.
func TestVhostDetailsOnARouterWithNoNames(t *testing.T) {
	r, err := router.New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := r.VhostDetails(); len(got) != 0 {
		t.Errorf("a router with no names reports %d: %+v", len(got), got)
	}
}

// TestVhostDetailsConcurrentWithLiveLookups guards the lock the listing takes.
//
// The listing walks the same two maps a publisher writes and a request reads, so
// skipping the lock would be exactly as unsafe as skipping it on the hot path:
// reading a Go map while another goroutine writes it stops the process, mid
// request, with nothing recoverable. The bound is an iteration count rather than
// a wait for something to happen, so a failure is reported as one instead of
// running until the package times out.
func TestVhostDetailsConcurrentWithLiveLookups(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"seed.s.internal": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	const rounds = 300
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < rounds; i++ {
			_ = r.VhostDetails()
		}
	}()

	for i := 0; i < rounds; i++ {
		// Each publish is a distinct name, so this is a write on every turn
		// rather than an idempotent repeat that would leave the map untouched.
		_ = r.AddVhost(fmt.Sprintf("n%d.s.internal", i), 4000+i%100)
	}
	<-done

	if got := len(r.VhostDetails()); got == 0 {
		t.Error("nothing was published, so the readers were never racing a writer")
	}
}
