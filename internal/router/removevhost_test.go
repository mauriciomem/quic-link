package router_test

// Taking a published name back. The interesting cases are not the happy one:
// they are the name that belongs to the operator, the name that was never there,
// and the name that keeps answering after it is gone.

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mauriciomem/quic-link/internal/router"
)

func TestRemoveVhostWithdrawsANamePublishedWhileRunning(t *testing.T) {
	r, err := router.New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.AddVhost("rt.s.internal", 4000); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	shadowedBy, err := r.RemoveVhost("rt.s.internal")
	if err != nil {
		t.Fatalf("RemoveVhost: %v", err)
	}
	if shadowedBy != "" {
		t.Errorf("nothing covers the name, but a pattern was reported: %q", shadowedBy)
	}
	for _, d := range r.VhostDetails() {
		if d.Name == "rt.s.internal" {
			t.Errorf("the name is still published after being withdrawn: %+v", d)
		}
	}
}

// TestRemoveVhostRefusesAConfiguredNameAndSaysWhich covers the case that matters
// most: a caller must not be able to stop an agent serving something its operator
// set up. The refusal has to name what is in the way, or the caller cannot tell
// this from the name simply being absent.
func TestRemoveVhostRefusesAConfiguredNameAndSaysWhich(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"cfg.s.internal": "tcp://127.0.0.1:3000"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	_, err = r.RemoveVhost("cfg.s.internal")
	if err == nil {
		t.Fatal("a name from the agent's configuration was withdrawn by a caller")
	}
	if !errors.Is(err, router.ErrVhostImmutable) {
		t.Errorf("the refusal is not the one that means the name belongs to someone else: %v", err)
	}
	if errors.Is(err, router.ErrVhostAbsent) {
		t.Error("a configured name was reported as absent, which would send a caller looking " +
			"for a name that is right there")
	}
	if !strings.Contains(err.Error(), "configuration") {
		t.Errorf("the refusal does not say what kind of entry is in the way: %v", err)
	}

	// And it is still there.
	var found bool
	for _, d := range r.VhostDetails() {
		if d.Name == "cfg.s.internal" {
			found = true
		}
	}
	if !found {
		t.Error("the configured name was removed despite the refusal")
	}
}

func TestRemoveVhostSaysWhenThereWasNothingToWithdraw(t *testing.T) {
	r, err := router.New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.RemoveVhost("nope.s.internal")
	if !errors.Is(err, router.ErrVhostAbsent) {
		t.Errorf("withdrawing a name nothing published reports %v, want the absent case", err)
	}
	if errors.Is(err, router.ErrVhostImmutable) {
		t.Error("an absent name was reported as belonging to somebody else")
	}
}

// TestRemoveVhostReportsAPatternThatResumesServing is the defect this step was
// nearly shipped without. A configured pattern can cover a published name; with
// the exact entry deleted the pattern answers again, at its own address. A caller
// told only "withdrawn" would believe the name was gone while it still served.
func TestRemoveVhostReportsAPatternThatResumesServing(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"*.s.internal": "tcp://127.0.0.1:3000"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	if err := r.AddVhost("rt.s.internal", 4000); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	shadowedBy, err := r.RemoveVhost("rt.s.internal")
	if err != nil {
		t.Fatalf("RemoveVhost: %v", err)
	}
	if shadowedBy != "*.s.internal" {
		t.Errorf("the pattern that resumed serving the name was reported as %q, want %q; a "+
			"withdrawal that leaves the name answered has to say so", shadowedBy, "*.s.internal")
	}
}

// TestRemoveVhostNeverTakesAPattern: a pattern is always the operator's, so the
// provenance check refuses it. Asserted separately because a future change to
// removal that also walked the pattern map would pass every test above.
func TestRemoveVhostNeverTakesAPattern(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"*.s.internal": "tcp://127.0.0.1:3000"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	if _, err := r.RemoveVhost("*.s.internal"); err == nil {
		t.Fatal("a pattern was withdrawn by a caller")
	}
	var still bool
	for _, d := range r.VhostDetails() {
		if d.Name == "*.s.internal" {
			still = true
		}
	}
	if !still {
		t.Error("the pattern is gone from the table after a refused withdrawal")
	}
}

// TestWithdrawingAnExactNameLeavesPatternsAlone is the other half, and the half a
// refusal test cannot cover: a successful withdrawal must touch only the name it
// was given. Removal that also reached into the pattern map would pass every
// refusal check above while quietly deleting a configured pattern each time a
// caller took back a name it covered.
func TestWithdrawingAnExactNameLeavesPatternsAlone(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"*.s.internal": "tcp://127.0.0.1:3000"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	if err := r.AddVhost("rt.s.internal", 4000); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	if _, err := r.RemoveVhost("rt.s.internal"); err != nil {
		t.Fatalf("RemoveVhost: %v", err)
	}

	var pattern bool
	for _, d := range r.VhostDetails() {
		if d.Name == "*.s.internal" {
			pattern = true
			if d.Provenance != router.ProvenanceConfig {
				t.Errorf("the pattern's provenance changed to %q", d.Provenance)
			}
		}
	}
	if !pattern {
		t.Error("withdrawing an exact name also deleted the configured pattern that covered it; " +
			"a caller taking back its own name must not remove the operator's")
	}
}

// TestRemoveVhostChecksAndDeletesUnderOneLock guards the window between deciding
// a name is safe to remove and removing it. The bound is an iteration count, so a
// failure is reported rather than running until the package times out.
func TestRemoveVhostChecksAndDeletesUnderOneLock(t *testing.T) {
	r, err := router.NewWithVhosts(nil, map[string]string{"seed.s.internal": "tcp://127.0.0.1:1"}, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	const rounds = 200
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = r.VhostDetails()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = r.AddVhost("churn.s.internal", 4000)
			_, _ = r.RemoveVhost("churn.s.internal")
		}
	}()
	wg.Wait()

	// The configured seed must have survived all of it.
	var seed bool
	for _, d := range r.VhostDetails() {
		if d.Name == "seed.s.internal" {
			seed = true
		}
	}
	if !seed {
		t.Error("a configured name was lost while names were being added and withdrawn")
	}
}
