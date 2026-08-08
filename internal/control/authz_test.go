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
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// pairStreams sets up an in-memory transport connection between two
// endpoints and returns one bidirectional stream opened on each side, paired
// with each other. Cleanup is registered with t.
func pairStreams(t *testing.T, name string) (client, server transport.Stream) {
	t.Helper()
	hub := mem.NewHub()
	srvT := hub.Transport(name + "-srv:1")
	cliT := hub.Transport(name + "-cli:1")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, name+"-srv:1")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { cliConn.CloseWithError(0, "test done") }) //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { srvConn.CloseWithError(0, "test done") }) //nolint:errcheck

	cliStream, err := cliConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	srvStream, err := srvConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	return cliStream, srvStream
}

// TestServe_DenyPolicy_ReachesCallerAsPermissionDenied proves the
// control-plane authorization check-point is actually consulted: a policy
// that denies every call must cause a real RPC, driven through a real gRPC
// client and server pair, to fail with a real PermissionDenied status at the
// caller — not a silently-empty successful response. This is the single most
// important test in this file: without it, a Policy field that nothing ever
// calls would be decoration, not a check-point.
func TestServe_DenyPolicy_ReachesCallerAsPermissionDenied(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "deny")

	deny := control.PolicyFunc(func(control.PeerIdentity, string) error {
		return errors.New("denied by test policy")
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
	_, err = client.Ping(callCtx, &controlpb.PingRequest{Nonce: 1})
	if err == nil {
		t.Fatal("Ping succeeded against a deny-all policy; the authorization check-point was not consulted")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Ping error = %v, want a status carrying codes.PermissionDenied", err)
	}

	cancel()
	<-serveDone
}

// TestServe_NilPolicy_DefaultsToAllowAll proves that a nil Policy behaves as
// allow-all, matching the rest of the tree's nil-means-allow-all convention
// (router.New's own policy parameter), so callers that have nothing to
// configure yet don't have to pass AllowAll{} explicitly.
func TestServe_NilPolicy_DefaultsToAllowAll(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "nilpolicy")

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
	if _, err := client.Ping(callCtx, &controlpb.PingRequest{Nonce: 42}); err != nil {
		t.Fatalf("Ping with a nil policy (want allow-all default): %v", err)
	}

	cancel()
	<-serveDone
}

// TestServe_PolicySeesRealPeerAndMethodName proves the policy is consulted
// with the actual peer identity Serve was given and the actual RPC method
// name being invoked, not placeholder or zero values.
func TestServe_PolicySeesRealPeerAndMethodName(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "recording")

	// The policy runs on a goroutine the gRPC server spins up to handle the
	// interceptor call — not the test goroutine. A plain variable written
	// there and read after client.Ping returns has no happens-before edge
	// the race detector can see: the RPC round trip completing is a real
	// ordering guarantee at the network layer, but it is invisible to the
	// detector, which only tracks edges through channels, mutexes, and
	// atomics. Sending the observed values on a channel and receiving them
	// here gives a real synchronization edge instrumented by the runtime.
	// The channel is buffered so the policy callback never blocks on a slow
	// or absent receiver.
	type recorded struct {
		peer   control.PeerIdentity
		method string
	}
	gotCh := make(chan recorded, 1)
	recording := control.PolicyFunc(func(peer control.PeerIdentity, method string) error {
		select {
		case gotCh <- recorded{peer: peer, method: method}:
		default:
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "abcd1234pin"}, recording)
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	if _, err := client.Ping(callCtx, &controlpb.PingRequest{Nonce: 7}); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	select {
	case got := <-gotCh:
		if got.peer.Pin != "abcd1234pin" {
			t.Errorf("policy saw peer.Pin = %q, want %q", got.peer.Pin, "abcd1234pin")
		}
		if got.method != "Ping" {
			t.Errorf("policy saw method = %q, want %q", got.method, "Ping")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy was never invoked — the authorization check-point was not consulted")
	}

	cancel()
	<-serveDone
}
