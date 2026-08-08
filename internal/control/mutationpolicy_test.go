package control

import (
	"strings"
	"testing"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// TestMutationPolicy_AMethodNobodyClassifiedIsRefused is the test the policy's
// whole shape exists for, and the one thing no test covered before: the answer
// for a call this build has never heard of.
//
// The rule is written as a list of what is safe without permission, so that
// anything else — including a method somebody adds later and forgets to think
// about — is refused until an operator says otherwise. Written the other way
// round, as a list of what to refuse, the same forgotten method would be
// permitted by default, and the first time that mattered would be the first
// time it was wrong.
//
// Both formulations agree about every method that exists today, which is
// exactly why this test uses a name that does not: nothing else can tell them
// apart.
func TestMutationPolicy_AMethodNobodyClassifiedIsRefused(t *testing.T) {
	const unclassified = "SomeMethodNobodyHasClassifiedYet"

	if err := (MutationPolicy{}).Authorize(PeerIdentity{}, unclassified); err == nil {
		t.Error("a method this build does not recognize was permitted without the operator's consent; " +
			"the rule must name what is safe, not what is dangerous, or anything forgotten is allowed")
	}
	if err := (MutationPolicy{AllowMutation: true}).Authorize(PeerIdentity{}, unclassified); err != nil {
		t.Errorf("an operator who allowed changes still could not make an unrecognized one: %v", err)
	}
	// The empty method name is the degenerate case of the same question.
	if err := (MutationPolicy{}).Authorize(PeerIdentity{}, ""); err == nil {
		t.Error("an empty method name was permitted without consent")
	}
}

// TestMutationPolicy_ReportingNeedsNoConsent guards the behaviour that shipped
// before any of this: an agent that refuses changes must still answer
// questions. A rule written the safe way round can easily refuse too much, and
// this is what would notice.
func TestMutationPolicy_ReportingNeedsNoConsent(t *testing.T) {
	for _, method := range []string{"Ping", "GetStatus"} {
		for _, p := range []MutationPolicy{{}, {AllowMutation: true}} {
			if err := p.Authorize(PeerIdentity{}, method); err != nil {
				t.Errorf("%s was refused (AllowMutation=%v): %v", method, p.AllowMutation, err)
			}
		}
	}
}

// TestMutationPolicy_ChangingNeedsConsentAndSaysSo covers the method that does
// exist, in both postures, and checks the refusal is something an operator can
// act on rather than a bare denial.
func TestMutationPolicy_ChangingNeedsConsentAndSaysSo(t *testing.T) {
	err := (MutationPolicy{}).Authorize(PeerIdentity{}, "AddVhost")
	if err == nil {
		t.Fatal("publishing a name was permitted without the operator's consent")
	}
	if !strings.Contains(err.Error(), "AddVhost") {
		t.Errorf("the refusal does not say which call was refused: %v", err)
	}
	if !strings.Contains(err.Error(), "operator") {
		t.Errorf("the refusal does not point at who can change it: %v", err)
	}
	if err := (MutationPolicy{AllowMutation: true}).Authorize(PeerIdentity{}, "AddVhost"); err != nil {
		t.Errorf("an operator who allowed changes was still refused: %v", err)
	}
}

// TestEveryServedMethodIsClassified reads the methods this agent actually
// serves out of the generated service description and requires each one to have
// been thought about.
//
// Without it, classification is a thing somebody has to remember, and the way
// forgetting shows up is silent: the call is refused, correctly, but the
// attempt is never written down — so an operator cannot find out it happened.
// This turns remembering into a build failure.
func TestEveryServedMethodIsClassified(t *testing.T) {
	if len(controlpb.Control_ServiceDesc.Methods) == 0 {
		t.Fatal("no methods found in the service description; this test is not checking anything")
	}
	for _, m := range controlpb.Control_ServiceDesc.Methods {
		readOnly := readOnlyMethods[m.MethodName]
		changes := changesTheAgent(m.MethodName)
		if readOnly == changes {
			t.Errorf("method %q is classified as both readable and changing, or as neither; "+
				"every served method must be one or the other", m.MethodName)
		}
		if changes {
			// A changing method must be refused by default. If a new one is
			// added and this fails, the method is not the problem — the
			// missing decision about it is.
			if err := (MutationPolicy{}).Authorize(PeerIdentity{}, m.MethodName); err == nil {
				t.Errorf("method %q changes this agent but is permitted with no consent", m.MethodName)
			}
		}
	}
}
