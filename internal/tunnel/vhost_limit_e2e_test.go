package tunnel_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// fillVhostTable publishes names directly into the route table until it holds
// as many as it will, so a test can then ask for one more over the network.
//
// The ceiling stops a check that never refuses from becoming a loop with no
// end. A test that hangs is not a control: it reports nothing at all, where a
// failing one names what broke.
func fillVhostTable(t *testing.T, rtr *router.Router) {
	t.Helper()
	const ceiling = 10000
	for i := 0; i < ceiling; i++ {
		err := rtr.AddVhost(fmt.Sprintf("svc%d.server1.internal", i), 3000+i%1000)
		if err == nil {
			continue
		}
		if errors.Is(err, router.ErrVhostLimit) {
			return
		}
		t.Fatalf("filling the table failed for a reason other than the bound: %v", err)
	}
	t.Fatalf("the table accepted %d names without ever reporting a bound", ceiling)
}

// TestAddVhostE2E_AFullTableReachesTheCallerAsItsOwnAnswer is the assertion the
// rest of this change is held together by.
//
// A refusal for a full table passes through five places on its way to whoever
// asked, and every one of them has an arm for "something I do not recognize"
// that degrades to the same sentence: the server is reconnecting, try again.
// So a single missing translation is silent — nothing fails to compile, no test
// about any one hop notices, and the caller is told to wait for a connection
// that was never broken, about a condition that will never clear on its own.
//
// This drives a real route table, filled until it refuses, through a real agent
// over a real session, and requires the code that comes back to be the one that
// means "there was no room", not the one that means "this agent hit a defect".
func TestAddVhostE2E_AFullTableReachesTheCallerAsItsOwnAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustVhostRouterFor(t, nil)
	fillVhostTable(t, rtr)

	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, tunnel.ServeOpts{AllowRemoteRouteMutation: true})
	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()

	_, err = addVhost(t, ctx, client, "one-too-many.server1.internal", 3000)
	if err == nil {
		t.Fatal("a name was published against a table that already holds as many as it will")
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("publishing against a full table returned %v, want %v — %v is what a caller "+
			"is told when nothing recognised the condition, and it is explained to an operator "+
			"as a session that is reconnecting",
			got, codes.ResourceExhausted, codes.Internal)
	}
}
