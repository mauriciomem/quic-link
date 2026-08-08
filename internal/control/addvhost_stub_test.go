package control_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

var errDeniedByTest = errors.New("denied by test policy")

// TestAddVhost_UnwiredAgentReportsUnimplemented pins the behaviour of an agent
// that serves the control stream but has no ability to change its own names —
// the state every agent is in until that capability is deliberately wired, and
// the state an agent built before this method existed is in permanently.
//
// Reporting it as unimplemented is the right answer for both, and it is
// deliberately NOT the same answer as "the operator has not allowed changes":
// those have different remedies — rebuild, versus edit a setting — and an
// operator sent to the wrong one loses time. Pinning it here means the
// distinction cannot be blurred later by accident.
func TestAddVhost_UnwiredAgentReportsUnimplemented(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "addvhost-unwired")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil)
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	_, err = client.AddVhost(callCtx, &controlpb.AddVhostRequest{
		Host: "grafana.server1.internal",
		Port: 3000,
	})
	if err == nil {
		t.Fatal("AddVhost succeeded against an agent with no way to change its names")
	}
	if got := status.Code(err); got != codes.Unimplemented {
		t.Errorf("AddVhost against an unwired agent returned code %v, want %v", got, codes.Unimplemented)
	}

	cancel()
	<-serveDone
}

// TestAddVhost_IsGatedByThePolicyCheckPoint proves the mutating method is
// authorized at dispatch like every other call, and specifically that it is
// covered by the same check-point rather than needing its own. A denial must
// win over the fact that the method is otherwise unimplemented: a caller that
// is not allowed to ask must not be able to learn anything about whether the
// capability exists.
func TestAddVhost_IsGatedByThePolicyCheckPoint(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "addvhost-denied")

	saw := make(chan string, 4)
	deny := control.PolicyFunc(func(_ control.PeerIdentity, method string) error {
		select {
		case saw <- method:
		default:
		}
		if method == "AddVhost" {
			return errDeniedByTest
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, deny)
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	_, err = client.AddVhost(callCtx, &controlpb.AddVhostRequest{
		Host: "grafana.server1.internal",
		Port: 3000,
	})
	if err == nil {
		t.Fatal("AddVhost succeeded despite a policy that denies it")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("AddVhost under a deny policy returned code %v, want %v — "+
			"the mutating method is not going through the authorization check-point", got, codes.PermissionDenied)
	}

	var methods []string
	for done := false; !done; {
		select {
		case m := <-saw:
			methods = append(methods, m)
		default:
			done = true
		}
	}
	var sawAddVhost bool
	for _, m := range methods {
		if m == "AddVhost" {
			sawAddVhost = true
		}
	}
	if !sawAddVhost {
		t.Errorf("the policy was never consulted for AddVhost by name; saw %v", methods)
	}

	cancel()
	<-serveDone
}
