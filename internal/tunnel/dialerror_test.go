package tunnel_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestServe_ADialFailureForANameSaysWhichNameFailed covers the log line an
// operator reads when a published name points somewhere nothing is listening —
// which is the ordinary case, because a name can be published before the
// service behind it is started.
//
// A stream that arrives by name carries no target, so a message built from the
// target field describes an empty one and sends whoever reads it looking in the
// route table for something that was never there. The name is the only thing
// that identifies such a request.
func TestServe_ADialFailureForANameSaysWhichNameFailed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sink := installRecordSink(t)

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// A name pointing at a port on the agent's own loopback where nothing is
	// listening: published successfully, undialable afterwards.
	rtr := mustVhostRouterFor(t, map[string]string{
		"grafana.server1.internal": "tcp://127.0.0.1:1",
	})
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()
	// The control stream has to be open before a data stream is served, and
	// this also proves the session is healthy before the failure under test.
	if _, err := client.Ping(ctx, &controlpb.PingRequest{Nonce: 1}); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	if err := tunnel.DoAttachHTTP(ctx, conn, nopReadWriteCloser{}, "grafana.server1.internal",
		"reqid-test", nil, nil); err == nil {
		t.Fatal("attaching to a name whose service is not listening reported success")
	}

	r := sink.await(t, "stream handler error")
	attrs := attrsOf(r)
	errText := attrs["err"]
	if strings.Contains(errText, `target ""`) {
		t.Errorf("the failure blames an empty target instead of naming the name that failed: %q", errText)
	}
	if !strings.Contains(errText, "grafana.server1.internal") {
		t.Errorf("the failure does not name what was asked for: %q", errText)
	}
}

// nopReadWriteCloser stands in for the local end of a splice that is never
// reached, because the dial on the far side fails first.
type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read([]byte) (int, error)    { return 0, nil }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }
