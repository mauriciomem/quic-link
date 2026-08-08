package control

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestContain_APanickingCallBecomesAnErrorInsteadOfEndingTheProcess is the
// whole point of the containment interceptor. Nothing above an RPC handler
// recovers, so before this existed one unexpected value in one call stopped the
// agent — and therefore every other session it was serving — at a moment a
// caller chose.
//
// The test drives the interceptor directly rather than through a session,
// because what is under test is the recovery itself: routing a panic through a
// real stream would prove the same thing while making the failure mode, if it
// regressed, be "the test binary dies" rather than a legible assertion.
func TestContain_APanickingCallBecomesAnErrorInsteadOfEndingTheProcess(t *testing.T) {
	srv := server{peer: PeerIdentity{Pin: "abcdefghijklmnop"}}
	info := &grpc.UnaryServerInfo{FullMethod: "/quiclink.v1.Control/AddVhost"}

	resp, err := srv.contain(context.Background(), struct{}{}, info,
		func(context.Context, any) (any, error) {
			panic("a deliberate panic standing in for any unexpected value")
		})

	if err == nil {
		t.Fatal("a panicking call reported success")
	}
	if resp != nil {
		t.Errorf("a panicking call returned a response as well as an error: %v", resp)
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("a contained panic reported code %v, want %v", got, codes.Internal)
	}
	// The caller is told the call failed and nothing more. A panic's value
	// describes this agent's own internals as often as anything else, and the
	// caller can do nothing with it either way.
	msg := status.Convert(err).Message()
	if strings.Contains(msg, "deliberate panic") {
		t.Errorf("the panic's own text was sent to the caller: %q", msg)
	}
}

// TestContain_AnOrdinaryFailureIsUnchanged checks the interceptor is invisible
// when nothing goes wrong. A recovery that also reshaped normal errors would
// quietly change what every existing call reports.
func TestContain_AnOrdinaryFailureIsUnchanged(t *testing.T) {
	srv := server{peer: PeerIdentity{Pin: "abcdefghijklmnop"}}
	info := &grpc.UnaryServerInfo{FullMethod: "/quiclink.v1.Control/GetStatus"}

	want := status.Error(codes.NotFound, "nothing here")
	_, err := srv.contain(context.Background(), struct{}{}, info,
		func(context.Context, any) (any, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Errorf("an ordinary error was altered on its way out: got %v, want %v", err, want)
	}

	const sentinel = "the answer"
	resp, err := srv.contain(context.Background(), struct{}{}, info,
		func(context.Context, any) (any, error) { return sentinel, nil })
	if err != nil {
		t.Errorf("a successful call reported an error: %v", err)
	}
	if resp != sentinel {
		t.Errorf("a successful call's response was altered: got %v", resp)
	}
}
