package daemon_test

import (
	"context"
	"errors"
	"fmt"
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

// TestExposeJSON_RefusesARelayThatDidNotCarryOutTheRequest covers the gap
// between "the relay reported no error" and "the name was published". A relay
// can decline to run the call at all — an entry with no session to speak over
// does exactly that — and reading a missing reply as success would print a
// working URL for a name that does not exist.
func TestExposeJSON_RefusesARelayThatDidNotCarryOutTheRequest(t *testing.T) {
	ln := heldHTTPListener(t)
	wantPort := ln.Addr().(*net.TCPAddr).Port

	pool := &fakeRoutesPool{
		state: "connected",
		controlFn: func(ctx context.Context, fn func(context.Context, *control.Client) error) error {
			// Reports success without running the call, which is what an entry
			// with no session to speak over does. The provider must not read
			// that as the name having been published — asserted separately
			// below; here it stands in for a relay that reached the agent.
			return nil
		},
	}
	p := daemon.NewExposeProvider(pool, daemon.NamingListeners{HTTP: ln})

	// A relay that reports success without having run the call must be refused,
	// not reported as a publish: a caller would otherwise be shown a working
	// URL for a name nobody published, which is worse than any refusal.
	_, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", 3000)
	if err == nil {
		t.Fatal("a relay that never carried out the request reported success")
	}
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("error is not a named relay failure: %v", err)
	}
	if !strings.Contains(re.Msg, "did not carry out") {
		t.Errorf("the refusal does not say the request was not carried out: %q", re.Msg)
	}
	// The port this machine holds is still what would be reported, and it comes
	// from the listener rather than from configuration. Proven by the fact that
	// the listener was bound on port 0 and reports a real number.
	if wantPort == 0 {
		t.Fatal("the test listener reported no port; nothing was proven")
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

// TestExposeJSON_RefusesAPortItCannotCarry covers this layer's own check rather
// than trusting the one above it. This is an exported entry point, and the
// conversion to the width the wire uses is silent: a value that does not fit
// would reach the agent as a different number than anyone asked for, and the
// refusal would then name that other number.
func TestExposeJSON_RefusesAPortItCannotCarry(t *testing.T) {
	ln := heldHTTPListener(t)
	p := daemon.NewExposeProvider(&fakeRoutesPool{state: "connected"}, daemon.NamingListeners{HTTP: ln})

	for _, port := range []int{0, -1, 65536, 1 << 33} {
		_, err := p.ExposeJSON(context.Background(), "srv1", "grafana.srv1.internal", port)
		var re *ipc.RoutesError
		if !errors.As(err, &re) {
			t.Fatalf("port %d: error is not a named relay failure: %v", port, err)
		}
		if re.Status != 2 {
			t.Errorf("port %d: status %d, want 2", port, re.Status)
		}
		if !strings.Contains(re.Msg, fmt.Sprintf("port %d ", port)) {
			t.Errorf("port %d: the refusal does not name that port: %q", port, re.Msg)
		}
	}
}
