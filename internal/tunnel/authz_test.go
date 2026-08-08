package tunnel_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestControlPolicy_SeesRealAuthenticatedPeer proves that serveControl
// actually threads the session's authenticated peer identity into the
// control package rather than discarding it. It drives a real pinning
// handshake between two identities and asserts the injected policy observed
// the exact pin the client authenticated with — not a zero value, and not a
// value the test constructed by hand.
func TestControlPolicy_SeesRealAuthenticatedPeer(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

	// The policy runs on a goroutine the gRPC server spins up to handle the
	// interceptor call — not the test goroutine, and not the goroutine
	// tunnel.Serve runs on. A plain variable written there and read after
	// control.Open returns has no happens-before edge the race detector can
	// see: the RPC round trip completing is a real ordering guarantee at the
	// network layer, but it is invisible to the detector, which only tracks
	// edges through channels, mutexes, and atomics. Sending the observed pin
	// on a channel and receiving it here gives a real synchronization edge
	// instrumented by the runtime, so the read is guaranteed to observe the
	// write. The channel is buffered so the policy callback never blocks on
	// a slow or absent receiver.
	gotPin := make(chan string, 1)
	recording := control.PolicyFunc(func(peer control.PeerIdentity, method string) error {
		select {
		case gotPin <- peer.Pin:
		default:
		}
		return nil
	})
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, tunnel.ServeOpts{ControlPolicy: recording})

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()

	select {
	case pin := <-gotPin:
		if pin != clientPin {
			t.Fatalf("control policy saw peer.Pin = %q, want the real client pin %q — "+
				"serveControl did not thread the authenticated peer identity through", pin, clientPin)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control policy was never invoked — serveControl did not consult it")
	}
}

// TestControlPolicy_DenyReachesRealClient proves a deny policy denies a real
// control-plane call end to end. control.Open's handshake itself calls Ping
// (via Establish) to bring the gRPC connection up, so a deny-all policy must
// make control.Open itself fail with a PermissionDenied status.
func TestControlPolicy_DenyReachesRealClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

	deny := control.PolicyFunc(func(control.PeerIdentity, string) error {
		return errors.New("denied by test policy")
	})
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, tunnel.ServeOpts{ControlPolicy: deny})

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	_, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err == nil {
		t.Fatal("control.Open succeeded against a deny-all control policy")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("control.Open error = %v, want a status carrying codes.PermissionDenied", err)
	}
}
