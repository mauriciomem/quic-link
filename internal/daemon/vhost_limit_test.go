package daemon_test

// Three relays end in the same place: a failure nobody classified is described
// to the operator as a session that is reconnecting. That sentence is a
// reasonable default for a call that dropped mid-flight and a wrong one for
// everything that will still be true in ten seconds. These are the cases where
// it is wrong, so each is asserted to say something else AND to not say that.
// Checking only for the right words would pass a message that said both.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// exhaustedPool answers every control call with the code an agent sends when a
// request was well formed and there was no room for it — and the code gRPC
// itself raises locally when a reply is larger than this side will accept.
func exhaustedPool(msg string) *fakeRoutesPool {
	return &fakeRoutesPool{
		state: "connected",
		controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
			return status.Error(codes.ResourceExhausted, msg)
		},
	}
}

func relayFailure(t *testing.T, err error) *ipc.RoutesError {
	t.Helper()
	if err == nil {
		t.Fatal("the relay reported success where it had nothing to report")
	}
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("the failure is not one the caller can act on: %v", err)
	}
	return re
}

// TestExposeJSON_AFullAgentIsNotDescribedAsReconnecting is the case this whole
// change exists to make legible. An agent that will hold no more names refuses
// a well-formed request, and the refusal will still be true on the next attempt
// — telling the operator to try again sends them round a loop that cannot end,
// about a session that was never broken.
func TestExposeJSON_AFullAgentIsNotDescribedAsReconnecting(t *testing.T) {
	ln := heldHTTPListener(t)
	p := daemon.NewExposeProvider(exhaustedPool("no room"), daemon.NamingListeners{HTTP: ln})

	_, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", 3000)
	re := relayFailure(t, err)

	if re.Status != 3 {
		t.Errorf("status %d, want 3: the command was well formed and the answer was no, "+
			"which is not a usage mistake", re.Status)
	}
	if strings.Contains(re.Msg, "reconnecting") {
		t.Errorf("a refusal that will not change on its own is described as a connection "+
			"that will come back: %q", re.Msg)
	}
	if !strings.Contains(re.Msg, "as many published names") {
		t.Errorf("the message does not say why the request was refused: %q", re.Msg)
	}
	// The remedy has to be reachable from the message: the names in the way are
	// listable, and that listing is the authority on which of them could be
	// taken back.
	if !strings.Contains(re.Msg, "quic-link vhosts") {
		t.Errorf("the message does not say how to see what is holding the room: %q", re.Msg)
	}
}

// TestVhostsJSON_ARepliedListingTooLargeIsNotDescribedAsReconnecting covers what
// capping this agent does nothing about.
//
// The bound belongs to whichever build is answering. A peer running an older
// build, a modified one, or a later one whose listing carries more per name can
// all send a reply this daemon will not accept in one message, and gRPC refuses
// it here rather than at the far end. Nothing about that resolves by waiting,
// and the limit is on this machine — so the message has to say so, or an
// operator goes looking at the network.
func TestVhostsJSON_ARepliedListingTooLargeIsNotDescribedAsReconnecting(t *testing.T) {
	p := daemon.NewVhostsProvider(exhaustedPool("grpc: received message larger than max"))

	_, err := p.VhostsJSON(context.Background(), "srv")
	re := relayFailure(t, err)

	if re.Status != 3 {
		t.Errorf("status %d, want 3", re.Status)
	}
	if strings.Contains(re.Msg, "reconnecting") {
		t.Errorf("a reply that did not fit is described as a connection that will come back: %q", re.Msg)
	}
	if !strings.Contains(re.Msg, "limit on this machine") {
		t.Errorf("the message does not say where the limit is, so an operator would look at "+
			"the network: %q", re.Msg)
	}
	if strings.Contains(re.Msg, "received message larger than max") {
		t.Errorf("the message leaks the transport's own wording: %q", re.Msg)
	}
}

// TestRoutesJSON_ARepliedTableTooLargeIsNotDescribedAsReconnecting is the same
// hole in the other listing, and it is the older of the two. Nothing bounds a
// route table at all, so this is not a theoretical shape: an agent with enough
// routes reaches it with no caller doing anything unusual.
func TestRoutesJSON_ARepliedTableTooLargeIsNotDescribedAsReconnecting(t *testing.T) {
	p := daemon.NewRoutesProvider(exhaustedPool("grpc: received message larger than max"))

	_, err := p.RoutesJSON(context.Background(), "srv")
	re := relayFailure(t, err)

	if re.Status != 3 {
		t.Errorf("status %d, want 3", re.Status)
	}
	if strings.Contains(re.Msg, "reconnecting") {
		t.Errorf("a reply that did not fit is described as a connection that will come back: %q", re.Msg)
	}
	if !strings.Contains(re.Msg, "limit on this machine") {
		t.Errorf("the message does not say where the limit is: %q", re.Msg)
	}
	if strings.Contains(re.Msg, "received message larger than max") {
		t.Errorf("the message leaks the transport's own wording: %q", re.Msg)
	}
}
