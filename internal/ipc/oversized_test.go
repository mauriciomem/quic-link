package ipc_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// stubExpose is an ipc.ExposeProvider that returns whatever body a test hands
// it, so the size check on the way out can be driven without a real agent.
type stubExpose struct {
	body []byte
	err  error
}

func (s *stubExpose) ExposeJSON(context.Context, string, string, int) ([]byte, error) {
	return s.body, s.err
}

func startTestServerWithExpose(t *testing.T, expose ipc.ExposeProvider) string {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	srv.SetExpose(expose)
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

// TestRPCExpose_AnOversizedReplyIsANamedRefusal covers what a caller is told
// when a reply is too large for this socket to carry.
//
// The reply contains a name the far end chose, and escaping a hostile one can
// multiply its length several times over, so a reply that fitted where it came
// from can still be too big here. Without a check the write is simply refused
// further down and the caller is left holding a closed socket with no answer at
// all — which is indistinguishable, from the caller's side, from the daemon
// having crashed.
func TestRPCExpose_AnOversizedReplyIsANamedRefusal(t *testing.T) {
	// Comfortably past the frame limit, so this does not depend on the exact
	// headroom reserved for the envelope.
	huge := []byte(`{"schema":1,"server":"srv1","host":"` + strings.Repeat("a", 200_000) + `","http_port":18080}`)
	sock := startTestServerWithExpose(t, &stubExpose{body: huge})

	_, err := ipc.NewClient(sock).ExposeJSON("srv1", "grafana.srv1.internal", 3000)
	if err == nil {
		t.Fatal("an oversized reply was relayed as a success")
	}
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("the caller got a bare transport error rather than a named refusal: %v", err)
	}
	if !strings.Contains(re.Msg, "too large") {
		t.Errorf("the refusal does not say the reply was too large: %q", re.Msg)
	}
	// The reason matters as much as the refusal: this is a limit of the local
	// socket, and an operator who reads it as a problem with the name or the
	// agent will go looking in the wrong place.
	if !strings.Contains(re.Msg, "local") {
		t.Errorf("the refusal does not say the limit is a local one: %q", re.Msg)
	}
}

// TestRPCExpose_ARepliableSizeStillSucceeds keeps the check above from passing
// because everything is refused.
func TestRPCExpose_ARepliableSizeStillSucceeds(t *testing.T) {
	body := []byte(`{"schema":1,"server":"srv1","host":"grafana.srv1.internal","http_port":18080}`)
	sock := startTestServerWithExpose(t, &stubExpose{body: body})

	got, err := ipc.NewClient(sock).ExposeJSON("srv1", "grafana.srv1.internal", 3000)
	if err != nil {
		t.Fatalf("ExposeJSON: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("body = %s, want %s", got, body)
	}
}
