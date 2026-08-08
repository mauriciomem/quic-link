package tunnel_test

import (
	"context"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// TestServe_NilRouteTable_StatusReportsEmptyRatherThanCrashing covers a
// session served without a route table at all. That is a valid configuration
// — a session can exist purely to carry the control stream — but it used to
// be a crash waiting for someone to ask a question: the adapter wrapping the
// absent table was itself a present value, so the check for "no table" could
// not see it, and the first status call dereferenced nothing.
//
// It matters more than a nil check usually would, because a panic inside a
// control-plane handler is not contained: the RPC does not merely fail, the
// whole agent process dies, taking every other session with it. So the
// assertion is deliberately that the call SUCCEEDS and reports an empty list,
// not merely that it returns some error.
func TestServe_NilRouteTable_StatusReportsEmptyRatherThanCrashing(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// No route table at all — the case every other test in this package
	// avoids by always supplying one.
	serverAddr := mustStartServe(t, ctx, serverTLS, nil)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open against a session with no route table: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
	defer callCancel()
	resp, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus against a session with no route table: %v", err)
	}
	if got := len(resp.GetRoutes()); got != 0 {
		t.Errorf("GetStatus returned %d routes for a session with no route table, want 0", got)
	}
}
