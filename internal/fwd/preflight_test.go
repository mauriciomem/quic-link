package fwd_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/fwd"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// fixedErrAttacher always returns err from Attach.
type fixedErrAttacher struct{ err error }

func (a *fixedErrAttacher) Attach(_, _ string, _ map[string]string) (net.Conn, error) {
	return nil, a.err
}

// pipeAttacher always returns one side of a net.Pipe() pair from Attach,
// closing the OTHER side once returned so Preflight's reset is observable
// without needing a real listener.
type pipeAttacher struct {
	closed chan struct{}
}

func newPipeAttacher() *pipeAttacher { return &pipeAttacher{closed: make(chan struct{}, 1)} }

func (a *pipeAttacher) Attach(_, _ string, _ map[string]string) (net.Conn, error) {
	local, remote := net.Pipe()
	go func() {
		// Detect the peer side closing (Preflight resets the conn it got
		// back) by attempting a read that will return once local is closed.
		buf := make([]byte, 1)
		local.Read(buf) //nolint:errcheck
		a.closed <- struct{}{}
	}()
	return remote, nil
}

func TestPreflight_OK_ResetsThrowawayConn(t *testing.T) {
	t.Parallel()
	att := newPipeAttacher()
	res := fwd.Preflight(att, "server1", "pg")
	if res.Outcome != fwd.PreflightOK {
		t.Fatalf("Outcome = %v, want PreflightOK", res.Outcome)
	}
	// Preflight must have reset the throwaway connection rather than leaking
	// it: the detector goroutine's blocked Read unblocks the moment that
	// happens, which is real observable behavior, not a sleep.
	select {
	case <-att.closed:
	case <-time.After(3 * time.Second):
		t.Error("Preflight did not reset the throwaway conn on a successful attach")
	}
}

func TestPreflight_UnknownTarget_FatalExit5_WithGuidance(t *testing.T) {
	t.Parallel()
	target := "no-such-route"
	att := &fixedErrAttacher{err: &ipc.AttachStatusError{
		Status: 5,
		Msg:    tunnel.UnknownTargetMessage(target),
	}}
	res := fwd.Preflight(att, "server1", target)
	if res.Outcome != fwd.PreflightFatal {
		t.Fatalf("Outcome = %v, want PreflightFatal", res.Outcome)
	}
	if res.Status != 5 {
		t.Errorf("Status = %d, want 5", res.Status)
	}
	if res.Msg != tunnel.UnknownTargetMessage(target) {
		t.Errorf("Msg = %q, want the verbatim agent message", res.Msg)
	}
	if res.Guidance == "" {
		t.Error("expected 'add a route' guidance for the unknown-target case, got none")
	}
}

func TestPreflight_DialFailedOrDraining_FatalExit5_NoGuidance(t *testing.T) {
	t.Parallel()
	// Same exit code (5) as unknown-target, but a different message: the
	// guidance must NOT fire for dial-failed/draining, only for the exact
	// unknown-target wording.
	att := &fixedErrAttacher{err: &ipc.AttachStatusError{
		Status: 5,
		Msg:    "dial tcp 127.0.0.1:5432: connect: connection refused",
	}}
	res := fwd.Preflight(att, "server1", "pg")
	if res.Outcome != fwd.PreflightFatal {
		t.Fatalf("Outcome = %v, want PreflightFatal", res.Outcome)
	}
	if res.Guidance != "" {
		t.Errorf("Guidance = %q, want empty for a non-unknown-target status-5 refusal", res.Guidance)
	}
}

func TestPreflight_Unauthorized_FatalExit4(t *testing.T) {
	t.Parallel()
	att := &fixedErrAttacher{err: &ipc.AttachStatusError{Status: 4, Msg: "not authorized for \"pg\""}}
	res := fwd.Preflight(att, "server1", "pg")
	if res.Outcome != fwd.PreflightFatal {
		t.Fatalf("Outcome = %v, want PreflightFatal", res.Outcome)
	}
	if res.Status != 4 {
		t.Errorf("Status = %d, want 4", res.Status)
	}
	if res.Guidance != "" {
		t.Errorf("Guidance = %q, want empty for unauthorized", res.Guidance)
	}
}

func TestPreflight_NotReady_Warn(t *testing.T) {
	t.Parallel()
	att := &fixedErrAttacher{err: &ipc.AttachStatusError{Status: 3, Msg: "server \"server1\": not ready: reconnecting"}}
	res := fwd.Preflight(att, "server1", "pg")
	if res.Outcome != fwd.PreflightWarn {
		t.Fatalf("Outcome = %v, want PreflightWarn", res.Outcome)
	}
	if res.Msg == "" {
		t.Error("expected a diagnostic message for the warn case")
	}
}

func TestPreflight_DaemonAbsent(t *testing.T) {
	t.Parallel()
	att := &fixedErrAttacher{err: errors.Join(ipc.ErrDaemonAbsent, errors.New("dial unix: connect: connection refused"))}
	res := fwd.Preflight(att, "server1", "pg")
	if res.Outcome != fwd.PreflightDaemonAbsent {
		t.Fatalf("Outcome = %v, want PreflightDaemonAbsent", res.Outcome)
	}
}

func TestPreflight_SchemaMismatch_TreatedAsDaemonAbsent(t *testing.T) {
	t.Parallel()
	att := &fixedErrAttacher{err: errors.Join(ipc.ErrSchemaMismatch, errors.New("daemon speaks schema 2"))}
	res := fwd.Preflight(att, "server1", "pg")
	if res.Outcome != fwd.PreflightDaemonAbsent {
		t.Fatalf("Outcome = %v, want PreflightDaemonAbsent (stale socket is grouped with absent)", res.Outcome)
	}
}
