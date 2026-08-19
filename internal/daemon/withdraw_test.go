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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
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
