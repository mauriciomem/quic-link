package tunnel_test

// Withdrawing a name over a real session, against a real route table.
//
// The unit tests either side of this boundary each hold one end still: the route
// table's test supplies its own caller, and the control server's test supplies
// its own table. Neither would notice an adapter that dropped a value between
// them, because the adapter is the one piece both of them stub out.

import (
	"context"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// withdrawVhost asks a live agent to take a name back.
func withdrawVhost(t *testing.T, ctx context.Context, c *control.Client, host string) (*controlpb.RemoveVhostResponse, error) {
	t.Helper()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.RemoveVhost(callCtx, &controlpb.RemoveVhostRequest{Host: host})
}

// vhostRigWith starts a real agent over a real QUIC session whose route table
// already publishes the given names, and returns a control client for it.
func vhostRigWith(t *testing.T, ctx context.Context, hosts map[string]string, opts tunnel.ServeOpts) *control.Client {
	t.Helper()
	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustVhostRouterFor(t, hosts)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, opts)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// TestRemoveVhostE2E_TheShadowAddressSurvivesEveryHop is the assertion the rest
// of this change rests on.
//
// The address is read out of the route table under the lock that performed the
// deletion, handed to an adapter, returned through an interface, written into a
// reply and encoded onto the wire. Four of those five hops have a test that
// stubs out the others, and none of them would fail if a hop returned the empty
// string: the reply still arrives, the withdrawal still succeeds, and the only
// symptom is a line of output that stops halfway through a sentence.
//
// So this drives the whole path. A configured pattern covers a name published at
// runtime, and after the withdrawal the reply has to name both the pattern and
// the address the pattern points at — deliberately a different port from the one
// the withdrawn entry used, so a hop that reported the wrong entry's address
// would be as visible as one that reported none.
func TestRemoveVhostE2E_TheShadowAddressSurvivesEveryHop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const pattern = "*.server1.internal"
	const patternAddr = "tcp://127.0.0.1:3000"
	client := vhostRigWith(t, ctx,
		map[string]string{pattern: patternAddr},
		tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	if _, err := addVhost(t, ctx, client, "grafana.server1.internal", 4000); err != nil {
		t.Fatalf("publishing the name to be withdrawn: %v", err)
	}

	resp, err := withdrawVhost(t, ctx, client, "grafana.server1.internal")
	if err != nil {
		t.Fatalf("RemoveVhost: %v", err)
	}
	if resp.GetShadowedBy() != pattern {
		t.Errorf("the pattern that resumed serving the name is reported as %q, want %q",
			resp.GetShadowedBy(), pattern)
	}
	if resp.GetShadowedByAddress() != patternAddr {
		t.Errorf("the address the pattern points at is reported as %q, want %q; a caller told "+
			"the name still answers and not where cannot act on either half",
			resp.GetShadowedByAddress(), patternAddr)
	}
}

// TestRemoveVhostE2E_NothingTakesOverAndBothFieldsStayEmpty is the control for
// the test above: without a covering pattern the same path must produce neither
// field. A hop that filled the address in from the withdrawn entry itself would
// pass the test above — the entry and the pattern would both be present — and
// fail here, where there is nothing that could honestly answer.
func TestRemoveVhostE2E_NothingTakesOverAndBothFieldsStayEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := vhostRigWith(t, ctx, nil, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	if _, err := addVhost(t, ctx, client, "grafana.server1.internal", 4000); err != nil {
		t.Fatalf("publishing the name to be withdrawn: %v", err)
	}

	resp, err := withdrawVhost(t, ctx, client, "grafana.server1.internal")
	if err != nil {
		t.Fatalf("RemoveVhost: %v", err)
	}
	if resp.GetShadowedBy() != "" || resp.GetShadowedByAddress() != "" {
		t.Errorf("nothing covers the name, but the reply names pattern %q at address %q",
			resp.GetShadowedBy(), resp.GetShadowedByAddress())
	}
}
