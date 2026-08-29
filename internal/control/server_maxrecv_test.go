package control_test

// server_maxrecv_test.go pins the gap where the agent's own gRPC server
// (Serve, in server.go) installed no grpc.MaxRecvMsgSize, so gRPC's stock
// 4 MiB default applied to every request an authenticated caller sent —
// while the client side (NewClient, client.go) has capped incoming replies
// at maxControlRecvMsgSize (64 KiB) since it was written, with a documented
// amplification rationale that applies with the roles reversed just as well.
//
// @spec-handoff
//
// Interface under test: control.Serve's grpc.NewServer construction.
//
// Expected behavior: a unary request whose marshalled size exceeds
// maxControlRecvMsgSize is rejected by the server with a gRPC status
// carrying codes.ResourceExhausted (gRPC's own class for "message larger
// than max"), rather than being fully unmarshaled and dispatched to its
// handler.
//
// Pre-fix failure mode: with no grpc.MaxRecvMsgSize configured, gRPC's
// stock 4 MiB default applies; a request comfortably over 64 KiB and
// comfortably under 4 MiB is accepted and reaches the handler.

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// allowingPublisher is a VhostPublisher that always succeeds, so a test can
// prove whether AddVhost's handler was ever reached: a request rejected at
// the transport layer (MaxRecvMsgSize) never calls it, while one merely
// denied by policy also never calls it — this test's point is to see that
// the request is rejected by SIZE alone, before any of that runs.
type allowingPublisher struct{ called chan struct{} }

func (p *allowingPublisher) AddVhost(string, int) error {
	if p.called != nil {
		close(p.called)
	}
	return nil
}

// TestServe_MaxRecvMsgSize_RejectsOversizedRequest proves the server-side
// cap exists and is enforced against an authenticated caller's REQUEST (the
// reverse direction from TestNewClient_MaxRecvMsgSize_RejectsOversizedReply,
// which covers the client capping a REPLY). 100 KiB of host comfortably
// exceeds maxControlRecvMsgSize (64 KiB) and comfortably undershoots gRPC's
// stock 4 MiB default, so this request would previously have been accepted
// and reached AddVhost's handler.
func TestServe_MaxRecvMsgSize_RejectsOversizedRequest(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "server-maxrecv")

	pub := &allowingPublisher{called: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil,
			control.ServeOpts{Names: pub})
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	huge := strings.Repeat("h", 100*1024)
	_, err = client.AddVhost(callCtx, &controlpb.AddVhostRequest{Host: huge, Port: 3000})
	if err == nil {
		t.Fatal("AddVhost succeeded with a request well over the server's configured MaxRecvMsgSize cap")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("AddVhost error = %v, want a status carrying codes.ResourceExhausted", err)
	}

	select {
	case <-pub.called:
		t.Fatal("the oversized request reached AddVhost's handler instead of being rejected at the transport layer")
	default:
	}

	cancel()
	<-serveDone
}
