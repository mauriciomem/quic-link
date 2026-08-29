package daemon_test

// The relay that carries a withdrawal. What matters here is that each refusal
// arrives as its own answer, and in particular that a name belonging to the
// agent's configuration is not reported as something a permission would fix.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

func withdrawWith(code codes.Code, msg string) (*ipc.RoutesError, error) {
	p := daemon.NewWithdrawProvider(&fakeRoutesPool{
		state: "connected",
		controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
			return status.Error(code, msg)
		},
	})
	_, err := p.WithdrawJSON(context.Background(), "srv", "n.srv.internal")
	var re *ipc.RoutesError
	if errors.As(err, &re) {
		return re, err
	}
	return nil, err
}

// TestAConfiguredNameIsNotReportedAsAPermissionAnOperatorCanGrant is the point of
// having a separate code for it. Reporting it as a permission problem would send
// somebody to change a setting that cannot make their own configuration remotely
// removable.
func TestAConfiguredNameIsNotReportedAsAPermissionAnOperatorCanGrant(t *testing.T) {
	re, err := withdrawWith(codes.FailedPrecondition, "not published over this connection")
	if re == nil {
		t.Fatalf("want an actionable failure, got %v", err)
	}
	if strings.Contains(re.Msg, "operator can allow") {
		t.Errorf("the message sends the caller to ask for a permission that cannot help: %q", re.Msg)
	}
	if !strings.Contains(re.Msg, "configuration") {
		t.Errorf("the message does not say why the name cannot be withdrawn: %q", re.Msg)
	}
	if re.Status != 3 {
		t.Errorf("status %d, want 3", re.Status)
	}
}

func TestAnAbsentNameSaysThereWasNothingToDo(t *testing.T) {
	re, err := withdrawWith(codes.NotFound, "not published")
	if re == nil {
		t.Fatalf("want an actionable failure, got %v", err)
	}
	if !strings.Contains(re.Msg, "nothing to withdraw") {
		t.Errorf("the message does not say the name was not there: %q", re.Msg)
	}
}

func TestEachWithdrawalRefusalHasItsOwnMessage(t *testing.T) {
	seen := map[string]codes.Code{}
	for _, c := range []codes.Code{
		codes.Unimplemented, codes.PermissionDenied, codes.NotFound,
		codes.FailedPrecondition, codes.InvalidArgument, codes.Unavailable,
	} {
		re, err := withdrawWith(c, "because")
		if re == nil {
			t.Fatalf("%v: want an actionable failure, got %v", c, err)
		}
		if prev, dup := seen[re.Msg]; dup {
			t.Errorf("%v and %v produce the same message %q, so a caller cannot tell them apart",
				c, prev, re.Msg)
		}
		seen[re.Msg] = c
	}
}

// TestWithdrawJSON_AgentTextIsNotSanitizedTwice is the regression test for
// the nested-truncation-marker defect on this relay's InvalidArgument case:
// withdrawFailure used to sanitize the agent's own gRPC status text inline
// before handing the RoutesError to the relay, which sanitizes the whole
// Msg again at the one documented boundary (routesErrorResponse in
// internal/ipc/server.go). This asserts the RoutesError this package hands
// to the relay carries the agent's text unmodified, so there is exactly one
// sanitizing pass between the agent and the operator.
func TestWithdrawJSON_AgentTextIsNotSanitizedTwice(t *testing.T) {
	agentText := "invalid host: " + strings.Repeat("x", 300)
	re, err := withdrawWith(codes.InvalidArgument, agentText)
	if re == nil {
		t.Fatalf("want an actionable failure, got %v", err)
	}
	if !strings.Contains(re.Msg, agentText) {
		t.Errorf("RoutesError.Msg = %q, want the agent's text carried unmodified "+
			"(sanitisation belongs at the relay boundary, not here)", re.Msg)
	}
}

// TestASuccessfulWithdrawalSaysWhenTheNameStillAnswers covers the shadow report
// crossing the relay: a withdrawal can be true and leave the name served.
func TestASuccessfulWithdrawalSaysWhenTheNameStillAnswers(t *testing.T) {
	p := daemon.NewWithdrawProvider(&fakeRoutesPool{
		state: "connected",
		controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
			return nil // the provider tolerates an empty reply
		},
	})
	raw, err := p.WithdrawJSON(context.Background(), "srv", "n.srv.internal")
	if err != nil {
		t.Fatalf("WithdrawJSON: %v", err)
	}
	var snap daemon.WithdrawSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Schema != 1 {
		t.Errorf("document version %d, want 1", snap.Schema)
	}
	// Nothing took over here, so the field must be absent rather than empty:
	// a reader should not have to distinguish "" from "no pattern".
	if strings.Contains(string(raw), "shadowed_by") {
		t.Errorf("the document names a pattern when none took over: %s", raw)
	}
	// Same for the address, and asserted on the bytes for the same reason: a
	// struct field reads as "" whether the key was absent or present-and-empty,
	// so decoding first would hide exactly the difference under test. The
	// substring above happens to cover this one, which is why it is spelled out
	// separately — a later rename of either key must not silently stop checking
	// the other.
	if strings.Contains(string(raw), "shadowed_by_address") {
		t.Errorf("the document names an address when nothing took over: %s", raw)
	}
}

// shadowingAgentServer answers a withdrawal the way an agent does when a
// configured pattern covers the name that was just taken back.
type shadowingAgentServer struct {
	controlpb.UnimplementedControlServer
}

func (shadowingAgentServer) RemoveVhost(_ context.Context, req *controlpb.RemoveVhostRequest) (*controlpb.RemoveVhostResponse, error) {
	return &controlpb.RemoveVhostResponse{
		Host:              req.GetHost(),
		ShadowedBy:        "*.srv.internal",
		ShadowedByAddress: "tcp://127.0.0.1:3000",
	}, nil
}

// newShadowingAgentClient builds a real *control.Client against a real gRPC
// server that reports a pattern and its address, using the same in-memory stream
// pairing the stale-agent client in routes_test.go does.
func newShadowingAgentClient(t *testing.T) *control.Client {
	t.Helper()
	cliStream, srvStream := pairControlStreams(t, "withdraw-shadow")

	gs := grpc.NewServer()
	controlpb.RegisterControlServer(gs, shadowingAgentServer{})
	ln := control.NewSingleConnListener(control.NewConn(srvStream))
	go gs.Serve(ln) //nolint:errcheck
	t.Cleanup(gs.Stop)

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// TestWithdrawJSONCarriesWhereTheNameIsAnsweredNow drives the provider against a
// real client and a real reply, so the field has to be read off the reply rather
// than merely exist on the document type. A provider that declared the field and
// never populated it would satisfy a struct-level test and produce a document
// that says the name still answers and never says where.
func TestWithdrawJSONCarriesWhereTheNameIsAnsweredNow(t *testing.T) {
	agent := newShadowingAgentClient(t)
	p := daemon.NewWithdrawProvider(&fakeRoutesPool{
		state: "connected",
		controlFn: func(ctx context.Context, fn func(context.Context, *control.Client) error) error {
			return fn(ctx, agent)
		},
	})

	raw, err := p.WithdrawJSON(context.Background(), "srv", "n.srv.internal")
	if err != nil {
		t.Fatalf("WithdrawJSON: %v", err)
	}
	var snap daemon.WithdrawSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.ShadowedBy != "*.srv.internal" {
		t.Errorf("the pattern that took over is reported as %q", snap.ShadowedBy)
	}
	if snap.ShadowedByAddress != "tcp://127.0.0.1:3000" {
		t.Errorf("the address the pattern points at is reported as %q, want %q",
			snap.ShadowedByAddress, "tcp://127.0.0.1:3000")
	}
	// The key a script reads, not just the Go field name behind it.
	if !strings.Contains(string(raw), `"shadowed_by_address":"tcp://127.0.0.1:3000"`) {
		t.Errorf("the document does not carry the agreed key and value: %s", raw)
	}
}

// TestWithdrawingFromADegradedSessionSaysWhich reuses the state table: a caller
// who cannot withdraw needs to know whether the server is off, connecting,
// waiting, or permanently rejected.
func TestWithdrawingFromADegradedSessionSaysWhich(t *testing.T) {
	for _, state := range []string{"disabled", "connecting", "listening", "auth_failed"} {
		p := daemon.NewWithdrawProvider(&fakeRoutesPool{
			state: state,
			controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
				t.Errorf("%s: the relay called an agent that has no live client", state)
				return nil
			},
		})
		_, err := p.WithdrawJSON(context.Background(), "srv", "n.srv.internal")
		var re *ipc.RoutesError
		if !errors.As(err, &re) {
			t.Errorf("%s: want an actionable failure, got %v", state, err)
			continue
		}
		if re.Status != 3 {
			t.Errorf("%s: status %d, want 3", state, re.Status)
		}
	}
}
