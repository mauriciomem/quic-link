package control_test

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

// hugeRouteSource reports n routes with a padded address, so the marshalled
// GetStatus reply comfortably exceeds any small cap under test regardless of
// exact proto framing overhead. It is a legitimate RouteSource — the fake
// lives at the same boundary control.status_test.go already fakes (route
// data), not at the RPC or size-limiting logic under test.
type hugeRouteSource struct{ n int }

func (h hugeRouteSource) RouteDetails() []control.RouteDetail {
	out := make([]control.RouteDetail, h.n)
	for i := range out {
		out[i] = control.RouteDetail{
			Name:    "route-padding-name",
			Address: strings.Repeat("x", 200),
			Builtin: false,
		}
	}
	return out
}

// TestNewClient_MaxRecvMsgSize_RejectsOversizedReply proves the control
// client enforces an explicit cap on how large a single RPC reply it will
// accept, rather than inheriting gRPC's built-in 4 MiB default. 500 routes at
// ~200+ bytes each is comfortably over the client's configured cap (64 KiB)
// and comfortably under gRPC's stock default (4 MiB), so this reply would
// succeed silently if the cap were ever removed.
func TestNewClient_MaxRecvMsgSize_RejectsOversizedReply(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "maxrecv")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil,
			control.ServeOpts{Routes: hugeRouteSource{n: 500}})
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	_, err = client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
	if err == nil {
		t.Fatal("GetStatus succeeded despite a reply well over the client's configured MaxRecvMsgSize cap")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("GetStatus error = %v, want a status carrying codes.ResourceExhausted", err)
	}

	cancel()
	<-serveDone
}
