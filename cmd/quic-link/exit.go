package main

import (
	"errors"
	"fmt"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// exitCodeForError maps a fatal error to a process exit code.
// 2: usage/validation failure (missing required flag, bad value, etc.)
// 3: peer unreachable (UDP blocked, server not listening, handshake timeout);
//
//	also daemon-interaction failures (absent, stale schema, owner already running)
//
// 4: authentication failure (peer rejected our pin or we rejected theirs)
// 5: remote refused (unknown target, dial failed, draining) — via statusError
// 1: anything else (network failure, I/O error, etc.)
func exitCodeForError(err error) int {
	// errFinalExitCode carries a code that was already computed by the daemon
	// and must not be remapped. Check it first so it is never overridden by
	// a less-specific match below.
	var fe *errFinalExitCode
	if errors.As(err, &fe) {
		return fe.code
	}
	// ssh's own exit status passes through unchanged — this is the one verb
	// whose exit code is not this CLI's taxonomy at all.
	var ee *errExecExitCode
	if errors.As(err, &ee) {
		return ee.code
	}
	var se *statusError
	if errors.As(err, &se) {
		return exitCodeForStatus(se.status)
	}
	var ownerRunning *errOwnerRunningType
	var squatter *errSquatterType
	var dockerNotReady *errDockerNotReady
	var daemonNotRunning *errDaemonNotRunning
	switch {
	case errors.Is(err, transport.ErrUnreachable):
		return 3
	case errors.As(err, &daemonNotRunning):
		// fwd's own no-fallback rule: no daemon was ever reached.
		return 3
	case errors.As(err, &dockerNotReady):
		// docker-env's zero-port rule: keeps "eval $(quic-link docker-env)"
		// a safe no-op instead of exporting DOCKER_HOST to a dead port.
		return 3
	case errors.Is(err, transport.ErrAuthFailed):
		return 4
	case errors.Is(err, errUsage):
		return 2
	case errors.Is(err, config.ErrInvalid):
		return 2
	case errors.Is(err, ipc.ErrDaemonAbsent):
		// Daemon not running; the verb already printed the remedy.
		return 3
	case errors.Is(err, ipc.ErrSchemaMismatch):
		// Daemon is stale; the verb already printed the restart instruction.
		return 3
	case errors.As(err, &ownerRunning):
		// A live owner is already running; exit 3 so the operator knows to use
		// "quic-link status" instead of starting a second owner.
		return 3
	case errors.As(err, &squatter):
		// The socket is occupied by an unrecognized process. This is an
		// environment/usage problem (investigate the socket path), not a
		// transient daemon-absent condition.
		return 2
	default:
		return 1
	}
}

// exitCodeForStatus maps an agent response status to a process exit code.
// This mapping is a locked output contract (callers must not remap these):
// 0: ok
// 4: unauthorized (authz denied)
// 5: remote refused (unknown target, dial failed, or agent draining)
// 1: unexpected/unrecognised status
//
// The implementation delegates to proto.ExitCodeForStatus so the mapping lives
// in exactly one place and is shared with the daemon's attach relay.
func exitCodeForStatus(s proto.Status) int {
	return proto.ExitCodeForStatus(s)
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

// errFinalExitCode carries a process exit code that was already computed
// upstream (e.g. by the daemon's attach relay, which converts the agent's
// protocol status into a final code before sending the IPC ack). exitCodeForError
// passes this code through unchanged — it must never be remapped, because the
// original protocol status is no longer available at this point.
//
// This type also satisfies alreadyReportedErr so that main() does not emit a
// redundant slog.Error line when the agent's message was already written to
// stderr by the caller.
type errFinalExitCode struct {
	code int
	msg  string
}

func (e *errFinalExitCode) Error() string {
	// The message describes whatever actually failed and is set by the caller.
	// This deliberately adds no prefix of its own: an earlier version claimed
	// "attach refused" for every use, which was false for the several callers
	// where no attach was ever attempted — a disabled server, a server with no
	// address to dial — and sent readers looking at the agent for a problem
	// that was in their config. The refusal wording that IS about an attach
	// belongs to the IPC error type that genuinely represents one.
	return fmt.Sprintf("%s (exit %d)", e.msg, e.code)
}

// alreadyReported signals that the agent's message was already written to
// stderr so main() must not emit an additional slog.Error line.
func (e *errFinalExitCode) alreadyReported() bool { return true }
