package control

// Reporting what a name table holds is not changing it, so this must be
// callable by any authenticated peer without the agent's operator having
// permitted anything. That is the whole difference between this and publishing.

import (
	"context"
	"testing"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

type fixedVhosts struct{ details []VhostDetail }

func (f fixedVhosts) VhostDetails() []VhostDetail { return f.details }

func TestListVhostsNeedsNoConsentFromTheOperator(t *testing.T) {
	// The policy an agent gets when its operator has allowed nothing.
	p := MutationPolicy{}
	if err := p.Authorize(PeerIdentity{}, "ListVhosts"); err != nil {
		t.Errorf("listing published names was refused on an agent that allows no changes, "+
			"but listing changes nothing: %v", err)
	}
	// The contrast that gives the check meaning: publishing is refused there.
	if err := p.Authorize(PeerIdentity{}, "AddVhost"); err == nil {
		t.Error("publishing a name was allowed on an agent whose operator allowed nothing")
	}
}

func TestListVhostsReportsWhatTheSourceHolds(t *testing.T) {
	s := server{vhosts: fixedVhosts{details: []VhostDetail{
		{Name: "a.s.internal", Address: "tcp://127.0.0.1:1", Provenance: "config"},
		{Name: "b.s.internal", Address: "tcp://127.0.0.1:2", Provenance: "runtime"},
	}}}

	resp, err := s.ListVhosts(context.Background(), &controlpb.ListVhostsRequest{})
	if err != nil {
		t.Fatalf("ListVhosts: %v", err)
	}
	if len(resp.GetVhosts()) != 2 {
		t.Fatalf("got %d names, want 2", len(resp.GetVhosts()))
	}
	got := resp.GetVhosts()[1]
	if got.GetHost() != "b.s.internal" || got.GetProvenance() != "runtime" {
		t.Errorf("a name published while running is reported as host=%q provenance=%q",
			got.GetHost(), got.GetProvenance())
	}
}

// TestListVhostsWithNoSourceReportsNothingNotAnError: an agent that publishes
// no names is a valid configuration. Reporting an error for it would make a
// caller unable to tell "none" from "something went wrong".
func TestListVhostsWithNoSourceReportsNothingNotAnError(t *testing.T) {
	var s server
	resp, err := s.ListVhosts(context.Background(), &controlpb.ListVhostsRequest{})
	if err != nil {
		t.Fatalf("an agent with no names reported an error: %v", err)
	}
	if len(resp.GetVhosts()) != 0 {
		t.Errorf("an agent with no names reported %d of them", len(resp.GetVhosts()))
	}
}
