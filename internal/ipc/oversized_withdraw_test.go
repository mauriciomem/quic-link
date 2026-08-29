package ipc_test

// oversized_withdraw_test.go pins the gap where the withdraw relay is the
// one of four sibling relays (routes, vhosts, withdraw, expose) missing the
// frame-size check its three siblings all have — see the identical check in
// oversized_test.go for expose, and the "routes"/"vhosts" cases in
// server.go. Without it, an oversized withdraw reply leaves the caller
// holding a bare socket error indistinguishable from a dead daemon, instead
// of a named refusal.
//
// @spec-handoff
//
// Interface under test: ipc.Server's "withdraw" RPC case in handleRPC, via
// ipc.WithdrawProvider.
//
// Expected behavior: when a WithdrawProvider's WithdrawJSON returns a body
// whose JSON encoding is larger than the socket frame can carry once
// enveloped (maxFrameSize - routesBodyHeadroom), the server responds with a
// named, non-zero-status *ipc.RoutesError describing the size limit as
// local, rather than attempting the write and leaving the caller with a
// closed connection and no response frame.
//
// Pre-fix failure mode: WithdrawJSON's oversized body is passed straight to
// writeResponse/okResponse with no size check; the underlying writeFrame
// call refuses the oversized payload internally and the caller's read of
// the response frame fails with a bare EOF — ipc.Client.WithdrawJSON wraps
// it as "ipc: read withdraw response: EOF", carrying no *ipc.RoutesError at
// all, so errors.As fails and the caller cannot tell this apart from a dead
// daemon.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// stubWithdraw is a WithdrawProvider that returns whatever body/err a test
// hands it, mirroring stubExpose in oversized_test.go.
type stubWithdraw struct {
	body []byte
	err  error
}

func (s *stubWithdraw) WithdrawJSON(context.Context, string, string) ([]byte, error) {
	return s.body, s.err
}

func startTestServerWithWithdrawProvider(t *testing.T, withdraw ipc.WithdrawProvider) string {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	srv.SetWithdraw(withdraw)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sock
}

// TestRPCWithdraw_AnOversizedReplyIsANamedRefusal is the withdraw-relay
// counterpart of TestRPCExpose_AnOversizedReplyIsANamedRefusal. Withdraw's
// reply (daemon.WithdrawSnapshot) carries three agent-worded strings (Host,
// ShadowedBy, ShadowedByAddress), so it can exceed the frame the same way an
// expose reply can.
func TestRPCWithdraw_AnOversizedReplyIsANamedRefusal(t *testing.T) {
	huge := []byte(`{"schema":1,"server":"srv1","host":"n.srv1.internal",` +
		`"shadowed_by":"` + strings.Repeat("a", 200_000) + `","shadowed_by_address":"tcp://127.0.0.1:1"}`)
	sock := startTestServerWithWithdrawProvider(t, &stubWithdraw{body: huge})

	_, err := ipc.NewClient(sock).WithdrawJSON("srv1", "n.srv1.internal")
	if err == nil {
		t.Fatal("an oversized withdraw reply was relayed as a success")
	}
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("the caller got a bare transport error rather than a named refusal: %v", err)
	}
	if !strings.Contains(re.Msg, "too large") {
		t.Errorf("the refusal does not say the reply was too large: %q", re.Msg)
	}
	if !strings.Contains(re.Msg, "local") {
		t.Errorf("the refusal does not say the limit is a local one: %q", re.Msg)
	}
}

// TestRPCWithdraw_ARepliableSizeStillSucceeds keeps the check above from
// passing because everything is refused.
func TestRPCWithdraw_ARepliableSizeStillSucceeds(t *testing.T) {
	body := []byte(`{"schema":1,"server":"srv1","host":"n.srv1.internal"}`)
	sock := startTestServerWithWithdrawProvider(t, &stubWithdraw{body: body})

	got, err := ipc.NewClient(sock).WithdrawJSON("srv1", "n.srv1.internal")
	if err != nil {
		t.Fatalf("WithdrawJSON: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("body = %s, want %s", got, body)
	}
}
