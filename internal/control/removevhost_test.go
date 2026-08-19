package control

// Withdrawing changes what the agent serves, so it must be refused unless the
// operator allowed remote changes — and refused a second time by the capability
// simply not being there. The record of a refusal has to name what was asked for,
// because the refused case is the one an operator most needs to see.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

type fakeWithdrawer struct {
	shadowedBy string
	err        error
	called     string
}

func (f *fakeWithdrawer) RemoveVhost(host string) (string, error) {
	f.called = host
	return f.shadowedBy, f.err
}

func TestWithdrawingNeedsTheOperatorsConsent(t *testing.T) {
	p := MutationPolicy{}
	if err := p.Authorize(PeerIdentity{}, "RemoveVhost"); err == nil {
		t.Error("a name was withdrawable on an agent whose operator allowed no changes")
	}
	allowed := MutationPolicy{AllowMutation: true}
	if err := allowed.Authorize(PeerIdentity{}, "RemoveVhost"); err != nil {
		t.Errorf("withdrawing was refused on an agent that allows changes: %v", err)
	}
	// The contrast that gives this meaning: reading is allowed either way.
	if err := p.Authorize(PeerIdentity{}, "ListVhosts"); err != nil {
		t.Errorf("listing was refused, but listing changes nothing: %v", err)
	}
}

// TestWithdrawingWithoutTheCapabilityIsUnimplemented covers the second gate. The
// policy refuses such a call anyway; this makes sure there is nothing behind the
// refusal to reach even if it were wrong.
func TestWithdrawingWithoutTheCapabilityIsUnimplemented(t *testing.T) {
	var s server
	_, err := s.RemoveVhost(context.Background(), &controlpb.RemoveVhostRequest{Host: "a.s.internal"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("an agent with no way to withdraw reported %v, want unimplemented", status.Code(err))
	}
}

func TestWithdrawingReportsThePatternThatResumesServing(t *testing.T) {
	f := &fakeWithdrawer{shadowedBy: "*.s.internal"}
	s := server{withdraw: f}

	resp, err := s.RemoveVhost(context.Background(), &controlpb.RemoveVhostRequest{Host: "rt.s.internal"})
	if err != nil {
		t.Fatalf("RemoveVhost: %v", err)
	}
	if f.called != "rt.s.internal" {
		t.Errorf("the withdrawer was asked about %q", f.called)
	}
	if resp.GetShadowedBy() != "*.s.internal" {
		t.Errorf("the pattern that took over is reported as %q", resp.GetShadowedBy())
	}
}

// TestAConfiguredNameIsNotAPermissionProblem is the distinction that keeps an
// operator from being sent to change a setting that cannot help. No permission
// makes somebody's own configuration remotely removable.
func TestAConfiguredNameIsNotAPermissionProblem(t *testing.T) {
	s := server{withdraw: &fakeWithdrawer{err: ErrNameNotOurs}}
	_, err := s.RemoveVhost(context.Background(), &controlpb.RemoveVhostRequest{Host: "cfg.s.internal"})

	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("a configured name was refused as %v; that invites asking for a permission "+
			"nobody can grant", got)
	}
	if status.Code(err) == codes.PermissionDenied {
		t.Error("a configured name was reported as a permission problem")
	}
}

func TestAnAbsentNameAndAConfiguredNameAreDifferentAnswers(t *testing.T) {
	absent := server{withdraw: &fakeWithdrawer{err: ErrNameAbsent}}
	_, aerr := absent.RemoveVhost(context.Background(), &controlpb.RemoveVhostRequest{Host: "x.s.internal"})
	if status.Code(aerr) != codes.NotFound {
		t.Errorf("an absent name was reported as %v, want not-found", status.Code(aerr))
	}

	notOurs := server{withdraw: &fakeWithdrawer{err: ErrNameNotOurs}}
	_, nerr := notOurs.RemoveVhost(context.Background(), &controlpb.RemoveVhostRequest{Host: "y.s.internal"})
	if status.Code(aerr) == status.Code(nerr) {
		t.Error("a name that is absent and a name that belongs to the operator get the same " +
			"answer, so a caller cannot tell which it is")
	}
}

// TestTheNameIsRecordedWhenAWithdrawalIsRefused covers the hole that the audit
// path would otherwise have: it extracts the name by request type, and a type it
// does not recognise reports nothing. A refusal logged without the name is the
// one record an operator most needs and cannot use.
func TestTheNameIsRecordedWhenAWithdrawalIsRefused(t *testing.T) {
	got := auditedName(&controlpb.RemoveVhostRequest{Host: "rt.s.internal"})
	if got == "" {
		t.Fatal("a withdrawal request contributes no name to the audit record, so a refused " +
			"attempt would be logged without saying what was asked for")
	}
	if !strings.Contains(got, "rt.s.internal") {
		t.Errorf("the recorded name is %q", got)
	}
	// And the reason vocabulary distinguishes the cases rather than collapsing them.
	if withdrawReason(ErrNameAbsent) == withdrawReason(ErrNameNotOurs) {
		t.Error("two different refusals are recorded with the same reason")
	}
	if !errors.Is(ErrNameNotOurs, ErrNameNotOurs) {
		t.Error("sentinel comparison is broken")
	}
}
