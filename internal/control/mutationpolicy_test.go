package control

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

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

// methodsSomebodyThoughtAbout is the list of served methods a person has
// actually classified, maintained by hand.
//
// It exists to be a SECOND opinion, independent of the rule the code uses. The
// rule treats anything it does not recognize as a change, which is the right
// default — but it means the code cannot tell "somebody decided this is a
// change" apart from "nobody has looked at this yet". Both answers are refusal.
// Only a list a human has to edit can tell them apart, which is why this is
// duplication on purpose rather than something to derive.
var methodsSomebodyThoughtAbout = map[string]bool{
	"Ping":      true,
	"GetStatus": true,
	"AddVhost":  true,
}

// TestEveryServedMethodIsClassified requires that every method this agent
// actually serves has been thought about.
//
// The methods are read out of the generated service description rather than
// listed here, so adding an RPC and forgetting to decide what it is becomes a
// failing test rather than a silence. The failure is not that the method is
// dangerous — an unclassified method is already refused — it is that nobody
// recorded a decision, and refusal-by-default is the same answer whether the
// decision was made or missed.
func TestEveryServedMethodIsClassified(t *testing.T) {
	if len(controlpb.Control_ServiceDesc.Methods) == 0 {
		t.Fatal("no methods found in the service description; this test is not checking anything")
	}
	for _, m := range controlpb.Control_ServiceDesc.Methods {
		if !methodsSomebodyThoughtAbout[m.MethodName] {
			t.Errorf("method %q is served but nobody has classified it. It is refused by "+
				"default, which is safe, but add it to the list in this test so the decision "+
				"is on the record — and to readOnlyMethods if it only reports.", m.MethodName)
			continue
		}
		// A method somebody decided is a change must actually be refused
		// without consent. This is what catches a method added to the
		// read-only list by mistake.
		if !readOnlyMethods[m.MethodName] {
			if err := (MutationPolicy{}).Authorize(PeerIdentity{}, m.MethodName); err == nil {
				t.Errorf("method %q changes this agent but is permitted with no consent", m.MethodName)
			}
		}
	}

	// The hand-maintained list must not outlive the methods in it, or it stops
	// describing this agent and starts describing an older one.
	served := make(map[string]bool, len(controlpb.Control_ServiceDesc.Methods))
	for _, m := range controlpb.Control_ServiceDesc.Methods {
		served[m.MethodName] = true
	}
	for name := range methodsSomebodyThoughtAbout {
		if !served[name] {
			t.Errorf("method %q is classified here but is no longer served; remove it so this "+
				"list stays a true statement about this agent", name)
		}
	}
}

// TestNoStreamingMethodEscapesTheCheckPoint guards a gap that does not exist
// yet and would be easy to open.
//
// Authorization and panic containment are installed for calls that send one
// request and get one reply. A streaming method would not pass through either:
// it needs its own interceptors, and adding the method without them would put a
// call outside the check-point that every call is supposed to go through — the
// one property that is unconditional here regardless of what the policy
// currently permits.
//
// So this asserts there are no streaming methods. When the first one is wanted,
// this test fails and says what has to happen first.
func TestNoStreamingMethodEscapesTheCheckPoint(t *testing.T) {
	if n := len(controlpb.Control_ServiceDesc.Streams); n != 0 {
		t.Errorf("%d streaming method(s) are served, but only single-request calls pass "+
			"through the authorization check-point and the panic containment. Install stream "+
			"equivalents of both before serving a streaming method.", n)
	}
}

// TestAuditUsesTheSameClassificationAsThePolicy is what makes "one decision, not
// two" true rather than merely intended.
//
// Refusing a call and recording that it was attempted are separate pieces of
// code. If each decided for itself which calls matter, they would eventually
// disagree, and the way that disagreement shows up is the worst of both: a
// change refused correctly and recorded nowhere, so an operator cannot find out
// anyone tried.
//
// It drives the real check-point with a method nothing has classified, and
// requires both a refusal and a record. A test naming a method that a shared
// rule and a separate list would agree about cannot tell the two arrangements
// apart — which is exactly how a second list went unnoticed once already.
func TestAuditUsesTheSameClassificationAsThePolicy(t *testing.T) {
	const unclassified = "SomeMethodNobodyHasClassifiedYet"

	records := make(chan slog.Record, 8)
	prev := slog.Default()
	slog.SetDefault(slog.New(recordCollector{out: records}))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := server{peer: PeerIdentity{Pin: "abcdefghijklmnop"}, policy: MutationPolicy{}}
	_, err := srv.authorize(context.Background(), struct{}{},
		&grpc.UnaryServerInfo{FullMethod: "/quiclink.v1.Control/" + unclassified},
		func(context.Context, any) (any, error) {
			t.Error("an unclassified method reached its handler")
			return nil, nil
		})
	if err == nil {
		t.Fatal("an unclassified method was permitted with no consent")
	}

	select {
	case r := <-records:
		if r.Message != "route mutation denied" {
			t.Errorf("the recorded line is %q, want the refusal of a change", r.Message)
		}
	case <-time.After(5 * time.Second):
		t.Error("a refused change to an unclassified method was recorded nowhere. The refusal " +
			"and the record must reach the same conclusion from the same place, or a call can " +
			"be refused with nothing to show anyone tried.")
	}
}

// recordCollector captures whole log records so a test can check which line was
// written rather than searching rendered text for a word.
type recordCollector struct{ out chan slog.Record }

func (recordCollector) Enabled(context.Context, slog.Level) bool { return true }
func (c recordCollector) Handle(_ context.Context, r slog.Record) error {
	select {
	case c.out <- r.Clone():
	default:
	}
	return nil
}
func (c recordCollector) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c recordCollector) WithGroup(string) slog.Handler      { return c }
