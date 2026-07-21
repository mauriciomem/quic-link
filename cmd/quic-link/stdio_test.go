package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// TestStatusErrorExitCode verifies that a statusError is mapped to the correct
// process exit code via exitCodeForError, covering all relevant status values.
func TestStatusErrorExitCode(t *testing.T) {
	cases := []struct {
		status   proto.Status
		wantCode int
	}{
		{proto.StatusUnknownTarget, 5},
		{proto.StatusUnauthorized, 4},
		{proto.StatusDialFailed, 5},
		{proto.StatusDraining, 5},
		{proto.StatusBadHeader, 1},
		{proto.StatusUnsupportedVersion, 1},
	}
	for _, tc := range cases {
		se := &statusError{status: tc.status, msg: "test message"}
		got := exitCodeForError(se)
		if got != tc.wantCode {
			t.Errorf("exitCodeForError(statusError{%v}) = %d, want %d",
				tc.status, got, tc.wantCode)
		}
	}
}

// TestStatusErrorAlreadyReported verifies that statusError satisfies the
// alreadyReportedErr interface, so main() skips the generic slog.Error line
// for remote-refusal cases where the message was already written to stderr.
func TestStatusErrorAlreadyReported(t *testing.T) {
	se := &statusError{status: proto.StatusUnknownTarget, msg: "no target"}

	var ar alreadyReportedErr
	if !errors.As(se, &ar) {
		t.Fatal("statusError does not satisfy alreadyReportedErr interface")
	}
	if !ar.alreadyReported() {
		t.Fatal("alreadyReported() = false, want true")
	}

	// A plain error must NOT satisfy the interface.
	plain := errors.New("plain error")
	var ar2 alreadyReportedErr
	if errors.As(plain, &ar2) {
		t.Fatal("plain errors.New unexpectedly satisfied alreadyReportedErr")
	}
}

// TestExitCodeForErrorPrecedence verifies the priority order in exitCodeForError:
// auth failure (4) and usage error (2) still take their correct codes even
// when statusError is in the chain.
func TestExitCodeForErrorPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"auth failure", transport.ErrAuthFailed, 4},
		{"usage error", usageErrorf("missing flag"), 2},
		{"generic error", errors.New("random"), 1},
		{"statusError unknown_target", &statusError{status: proto.StatusUnknownTarget, msg: "x"}, 5},
		{"statusError unauthorized", &statusError{status: proto.StatusUnauthorized, msg: "x"}, 4},
		{"statusError dial_failed", &statusError{status: proto.StatusDialFailed, msg: "x"}, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeForError(tc.err); got != tc.wantCode {
				t.Errorf("exitCodeForError(%v) = %d, want %d", tc.err, got, tc.wantCode)
			}
		})
	}
}

// TestStatusErrorMessage verifies that statusError.Error() includes both the
// status name and the agent message, for readable log output.
func TestStatusErrorMessage(t *testing.T) {
	se := &statusError{status: proto.StatusUnknownTarget, msg: "no such target"}
	s := se.Error()
	if !strings.Contains(s, "unknown_target") {
		t.Errorf("Error() = %q, want it to contain the status name", s)
	}
	if !strings.Contains(s, "no such target") {
		t.Errorf("Error() = %q, want it to contain the agent message", s)
	}
}

// TestStdioRWInterfaces verifies at compile time and at runtime that stdioRW
// satisfies the interfaces expected by tunnel.Pipe:
//   - io.ReadWriteCloser (Read, Write, Close)
//   - CloseWrite() error (half-close propagation)
func TestStdioRWInterfaces(t *testing.T) {
	rw := &stdioRW{}

	// Compile-time checks (will not compile if methods are missing).
	type fullIface interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
		CloseWrite() error
	}
	var _ fullIface = rw

	// Runtime: CloseWrite on a live test process may succeed or fail depending
	// on whether os.Stdout is already closed. We only require it not to panic.
	_ = rw.CloseWrite()
}
