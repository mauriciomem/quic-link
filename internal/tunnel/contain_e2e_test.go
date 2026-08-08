package tunnel_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// panickingPublisher stands in for any capability that is handed something it
// did not expect. What it panics on does not matter; that a caller can reach it
// does.
type panickingPublisher struct{}

func (panickingPublisher) AddVhost(string, int) error {
	panic("a deliberate panic standing in for an unexpected value")
}

// TestContainE2E_APanicDoesNotEndTheAgent proves containment where it counts:
// through a real session, over a real transport, with a real client asking.
//
// If this regresses, the failure is not a red test — it is the test binary
// dying, because that is exactly what would happen to the agent. So the
// assertion that matters most is the one after it: the session is still usable
// and other calls still work, which is what "the blast radius is one call"
// actually means.
func TestContainE2E_APanicDoesNotEndTheAgent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	// The capability is supplied directly, so the panic happens inside a real
	// handler on a real server goroutine rather than in the test's own.
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, tunnel.ServeOpts{
		AllowRemoteRouteMutation: true,
		ControlNames:             panickingPublisher{},
	})

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()

	callCtx, cancelCall := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCall()
	_, err = client.AddVhost(callCtx, &controlpb.AddVhostRequest{
		Host: "grafana.server1.internal", Port: 3000,
	})
	if err == nil {
		t.Fatal("a call whose handler panicked reported success")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("a contained panic reached the caller as %v, want %v", got, codes.Internal)
	}

	// The agent is still here and still answering. This is the property the
	// containment exists for; the error code above is only how it is reported.
	if _, err := client.Ping(callCtx, &controlpb.PingRequest{Nonce: 7}); err != nil {
		t.Errorf("the session did not survive a panic in an unrelated call: %v", err)
	}
	if _, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{}); err != nil {
		t.Errorf("the agent stopped answering questions after a panic: %v", err)
	}
}
