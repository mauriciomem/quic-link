package daemon_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// heldHTTPListener stands in for the naming listener this machine actually
// holds. A real one is used rather than a fake, because the port reported has to
// be the port something is really bound to — that is the whole distinction
// between what this reports and what configuration merely intended.
func heldHTTPListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// TestExposeJSON_RefusesWhenThisMachineAnswersNoNames is the case a caller would
// otherwise find hardest to diagnose. Publishing would succeed on the agent and
// the name would still be unreachable from here, so nothing would be wrong
// anywhere a caller could look. It is refused before the agent is asked at all.
func TestExposeJSON_RefusesWhenThisMachineAnswersNoNames(t *testing.T) {
	p := daemon.NewExposeProvider(&fakeRoutesPool{state: "connected"}, daemon.NamingListeners{})

	_, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", 3000)
	if err == nil {
		t.Fatal("publishing was allowed on a daemon that answers no names")
	}
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("error is not a named relay failure: %v", err)
	}
	if !strings.Contains(re.Msg, "not answering names") {
		t.Errorf("the refusal does not say this machine answers no names: %q", re.Msg)
	}
}

// TestExposeJSON_ReportsThePortItIsActuallyHolding proves the reply carries the
// live port rather than a number from configuration, and carries it alongside
// the publish result rather than leaving a caller to ask separately — two calls
// could straddle a moment where the answer changed.
func TestExposeJSON_ReportsThePortItIsActuallyHolding(t *testing.T) {
	ln := heldHTTPListener(t)
	wantPort := ln.Addr().(*net.TCPAddr).Port

	pool := &fakeRoutesPool{
		state: "connected",
		controlFn: func(ctx context.Context, fn func(context.Context, *control.Client) error) error {
			// A nil client is never dereferenced here: the relay under test is
			// what is being checked, not the call it would make.
			return nil
		},
	}
	p := daemon.NewExposeProvider(pool, daemon.NamingListeners{HTTP: ln})

	body, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", 3000)
	if err != nil {
		t.Fatalf("ExposeJSON: %v", err)
	}
	var snap daemon.ExposeSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.HTTPPort != wantPort {
		t.Errorf("reported port %d, want the port actually bound, %d", snap.HTTPPort, wantPort)
	}
	if snap.Server != "srv1" {
		t.Errorf("reported server %q, want %q", snap.Server, "srv1")
	}
}

// TestExposeJSON_NamesEachWayTheAgentCanRefuse checks that conditions with
// different remedies arrive as different messages. One reason standing in for
// all of them would send an operator to change a setting when the real problem
// was a name already in use, or to talk to another machine's operator when the
// real problem was local.
func TestExposeJSON_NamesEachWayTheAgentCanRefuse(t *testing.T) {
	ln := heldHTTPListener(t)

	cases := []struct {
		name       string
		agentErr   error
		wantStatus uint
		wantPhrase string
	}{
		{
			name:       "an agent that cannot publish names",
			agentErr:   status.Error(codes.Unimplemented, "not implemented"),
			wantStatus: 3,
			wantPhrase: "cannot publish names",
		},
		{
			name:       "an agent whose operator refuses remote changes",
			agentErr:   status.Error(codes.PermissionDenied, "switched off"),
			wantStatus: 3,
			wantPhrase: "refuses remote changes",
		},
		{
			name:       "a name that is already published",
			agentErr:   status.Error(codes.AlreadyExists, "already published as something else"),
			wantStatus: 3,
			wantPhrase: "already publishes that name",
		},
		{
			name:       "a request the agent would not accept",
			agentErr:   status.Error(codes.InvalidArgument, "port 0 is outside the usable range"),
			wantStatus: 2,
			wantPhrase: "outside the usable range",
		},
		{
			name:       "a session that dropped mid-call",
			agentErr:   errors.New("connection lost"),
			wantStatus: 3,
			wantPhrase: "reconnecting",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pool := &fakeRoutesPool{
				state: "connected",
				controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
					return c.agentErr
				},
			}
			p := daemon.NewExposeProvider(pool, daemon.NamingListeners{HTTP: ln})

			_, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", 3000)
			var re *ipc.RoutesError
			if !errors.As(err, &re) {
				t.Fatalf("error is not a named relay failure: %v", err)
			}
			if re.Status != c.wantStatus {
				t.Errorf("status %d, want %d", re.Status, c.wantStatus)
			}
			if !strings.Contains(re.Msg, c.wantPhrase) {
				t.Errorf("message %q does not say %q", re.Msg, c.wantPhrase)
			}
		})
	}
}

// TestExposeJSON_RefusesAServerWithNoLiveSession reuses the state vocabulary the
// route-table read already established, so the two relays describe the same
// conditions the same way.
func TestExposeJSON_RefusesAServerWithNoLiveSession(t *testing.T) {
	ln := heldHTTPListener(t)
	for _, state := range []string{"disabled", "connecting", "listening", "auth_failed"} {
		t.Run(state, func(t *testing.T) {
			p := daemon.NewExposeProvider(&fakeRoutesPool{state: state}, daemon.NamingListeners{HTTP: ln})
			_, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", 3000)
			var re *ipc.RoutesError
			if !errors.As(err, &re) {
				t.Fatalf("error is not a named relay failure: %v", err)
			}
			if re.Status != 3 {
				t.Errorf("status %d, want 3", re.Status)
			}
		})
	}
}
