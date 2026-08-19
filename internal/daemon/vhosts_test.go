package daemon_test

// The relay that carries a published-name listing from an agent to whoever
// asked. Every way it can fail short of success has to be its own answer: a
// caller who cannot see a listing needs to know whether the server is switched
// off, still connecting, waiting to be called in, permanently rejected, running
// an agent too old to answer, or simply dropped mid-call. Collapsing those into
// one message is what makes an operator guess.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

func TestVhostsJSON_EveryDegradedStateHasItsOwnAnswer(t *testing.T) {
	cases := []struct {
		state   string
		wants   string
		wantsNo string
	}{
		{state: "disabled", wants: "disabled"},
		{state: "connecting", wants: "connecting"},
		{state: "listening", wants: "waiting"},
		// A permanent rejection must never be described as something that will
		// resolve itself, because nothing about it will.
		{state: "auth_failed", wants: "authentication", wantsNo: "reconnecting"},
	}

	for _, tc := range cases {
		p := daemon.NewVhostsProvider(&fakeRoutesPool{
			state: tc.state,
			controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
				t.Errorf("%s: the relay called the agent for a state that has no live client", tc.state)
				return nil
			},
		})
		_, err := p.VhostsJSON(context.Background(), "srv")
		if err == nil {
			t.Errorf("%s: a listing was produced for a session that has none", tc.state)
			continue
		}
		var re *ipc.RoutesError
		if !errors.As(err, &re) {
			t.Errorf("%s: the failure is not one the caller can act on: %v", tc.state, err)
			continue
		}
		if re.Status != 3 {
			t.Errorf("%s: status %d, want 3", tc.state, re.Status)
		}
		if !strings.Contains(re.Msg, tc.wants) {
			t.Errorf("%s: message %q does not name the situation", tc.state, re.Msg)
		}
		if tc.wantsNo != "" && strings.Contains(re.Msg, tc.wantsNo) {
			t.Errorf("%s: message %q describes it as something that will pass", tc.state, re.Msg)
		}
	}
}

// TestVhostsJSON_UnknownServerIsAUsageProblem separates a server the pool has
// never heard of from every state above, all of which name one it knows.
func TestVhostsJSON_UnknownServerIsAUsageProblem(t *testing.T) {
	p := daemon.NewVhostsProvider(&fakeRoutesPool{stateErr: errors.New(`no server named "nope"`)})
	_, err := p.VhostsJSON(context.Background(), "nope")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("want an actionable failure, got %v", err)
	}
	if re.Status != 2 {
		t.Errorf("status %d, want 2: a name the pool does not know is a mistake in the command", re.Status)
	}
}

// TestVhostsJSON_AnAgentTooOldSaysSoAndSaysWhatToDo covers the expected answer
// from an agent built before this existed. It is not an exceptional failure, and
// the remedy is specific.
func TestVhostsJSON_AnAgentTooOldSaysSoAndSaysWhatToDo(t *testing.T) {
	p := daemon.NewVhostsProvider(&fakeRoutesPool{
		state: "connected",
		controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
			return status.Error(codes.Unimplemented, "unknown method ListVhosts")
		},
	})
	_, err := p.VhostsJSON(context.Background(), "srv")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("want an actionable failure, got %v", err)
	}
	if !strings.Contains(re.Msg, "rebuild both ends") {
		t.Errorf("message %q does not say what to do about a version mismatch", re.Msg)
	}
	if strings.Contains(re.Msg, "unknown method") {
		t.Errorf("message %q leaks the remote call's own wording", re.Msg)
	}
}

// TestVhostsJSON_ReportsWhatTheAgentSaid is the success path, including the
// field that decides whether a name could later be withdrawn.
func TestVhostsJSON_ReportsWhatTheAgentSaid(t *testing.T) {
	p := daemon.NewVhostsProvider(&fakeRoutesPool{
		state: "connected",
		controlFn: func(ctx context.Context, fn func(context.Context, *control.Client) error) error {
			return nil // no client needed: the provider tolerates an empty reply
		},
	})
	raw, err := p.VhostsJSON(context.Background(), "srv")
	if err != nil {
		t.Fatalf("VhostsJSON: %v", err)
	}
	var snap daemon.VhostsSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Schema != 1 {
		t.Errorf("document version %d, want 1", snap.Schema)
	}
	if snap.Server != "srv" {
		t.Errorf("the document names server %q", snap.Server)
	}
	// Its own document, not folded into the status document: this one is fetched
	// live and can fail in ways that one cannot.
	if strings.Contains(string(raw), `"servers"`) {
		t.Errorf("the listing was folded into the status document: %s", raw)
	}
}
