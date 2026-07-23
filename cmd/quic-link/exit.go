package main

import (
	"errors"
	"fmt"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// exitCodeForError maps a fatal error to a process exit code.
// 2: usage/validation failure (missing required flag, bad value, etc.)
// 4: authentication failure (peer rejected our pin or we rejected theirs)
// 5: remote refused (unknown target, dial failed, draining) — via statusError
// 1: anything else (network failure, I/O error, etc.)
func exitCodeForError(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return exitCodeForStatus(se.status)
	}
	switch {
	case errors.Is(err, transport.ErrAuthFailed):
		return 4
	case errors.Is(err, errUsage):
		return 2
	case errors.Is(err, config.ErrInvalid):
		return 2
	default:
		return 1
	}
}

// exitCodeForStatus maps an agent response status to a process exit code.
// 0: ok
// 4: unauthorized (authz denied)
// 5: remote refused (unknown target, dial failed, or agent draining)
// 1: unexpected/unrecognised status
//
// This mapping is a locked output contract: callers must not remap these.
func exitCodeForStatus(s proto.Status) int {
	switch s {
	case proto.StatusOK:
		return 0
	case proto.StatusUnauthorized:
		return 4
	case proto.StatusUnknownTarget, proto.StatusDialFailed, proto.StatusDraining:
		return 5
	default:
		return 1
	}
}

// statusError wraps an agent response status and the verbatim message from the
// agent. The stdio verb returns this so main() can map it to the right exit
// code via exitCodeForStatus, and so the "already reported" interface tells
// main() NOT to emit a redundant slog.Error line (the agent message was already
// written to stderr at the point of refusal).
type statusError struct {
	status proto.Status
	msg    string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("agent: %s: %s", e.status, e.msg)
}

// alreadyReported signals that the error was already communicated to the user
// (the agent's refusal message was written to stderr verbatim). main() must
// NOT emit an additional slog.Error line for these errors.
func (e *statusError) alreadyReported() bool { return true }
