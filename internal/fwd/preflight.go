package fwd

import (
	"errors"
	"fmt"

	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// PreflightOutcome classifies the result of a startup preflight attach.
type PreflightOutcome int

const (
	// PreflightOK means the target validated: the caller should bind the
	// local port and print the CONTRACT line.
	PreflightOK PreflightOutcome = iota
	// PreflightWarn means a daemon-scoped, transient condition (the session
	// is still reconnecting, the server is unknown to this particular
	// daemon, or the daemon's own in-flight-attach cap was reached): the
	// caller should warn on stderr and bind and listen anyway, trusting the
	// accept loop's own attaches to succeed once the condition clears.
	PreflightWarn
	// PreflightFatal means an agent-scoped, authoritative, permanent
	// refusal from the remote route table: the caller must print Msg (and
	// Guidance, when set) to stderr and exit with Status, without ever
	// binding a local port.
	PreflightFatal
	// PreflightDaemonAbsent means no daemon is listening on the socket, or
	// the socket speaks a different schema: the caller must exit 3.
	PreflightDaemonAbsent
)

// PreflightResult is Preflight's return value.
type PreflightResult struct {
	Outcome PreflightOutcome
	// Status is the process exit code to use, meaningful when
	// Outcome == PreflightFatal (4 for unauthorized, 5 for unknown target,
	// dial failure, or draining — matching ipc.AttachStatusError.Status,
	// which is already the final exit code).
	Status int
	// Msg is the agent's verbatim refusal message (Fatal) or the daemon's
	// own diagnostic (Warn or DaemonAbsent).
	Msg string
	// Guidance is extra "add a route" text, set only for a Fatal outcome
	// whose Msg matches the exact unknown-target wording.
	Guidance string
}

// Preflight validates target against server's route table before the local
// port is bound, by performing one throwaway Attach and immediately
// resetting the resulting connection rather than ever splicing it. When the
// target is valid this costs one real connect-then-close against the target
// service, which that service may log; when the target is unknown it costs
// nothing remotely, because the agent resolves the name against its route
// table before dialing anything at all.
func Preflight(att Attacher, server, target string) PreflightResult {
	conn, err := att.Attach(server, target, nil)
	if err == nil {
		tunnel.ResetConn(conn)
		return PreflightResult{Outcome: PreflightOK}
	}

	if errors.Is(err, ipc.ErrDaemonAbsent) || errors.Is(err, ipc.ErrSchemaMismatch) {
		return PreflightResult{Outcome: PreflightDaemonAbsent, Msg: err.Error()}
	}

	var ae *ipc.AttachStatusError
	if errors.As(err, &ae) {
		if isAgentScoped(ae.Status) {
			res := PreflightResult{Outcome: PreflightFatal, Status: ae.Status, Msg: ae.Msg}
			if ae.Status == 5 && ae.Msg == tunnel.UnknownTargetMessage(target) {
				res.Guidance = fmt.Sprintf(
					"add a route named %q on the agent (agent --route %s=ADDR, "+
						"or a matching [agent.routes] config entry) or check for a typo",
					target, target)
			}
			return res
		}
		// Daemon-scoped: status 3 (not ready / unknown-to-this-daemon), or
		// anything else that is not 4/5 (e.g. the daemon's own in-flight-
		// attach cap). Transient by definition — warn and let the caller
		// proceed to bind and listen; the accept loop's own attaches get
		// another chance once the condition clears.
		return PreflightResult{Outcome: PreflightWarn, Msg: ae.Msg}
	}

	// Any other error shape (e.g. a hiccup on the socket dial itself, short
	// of a clean daemon-absent signal): be conservative and warn rather than
	// fail startup hard, on the same reasoning as the reconnecting-session
	// case above — a false startup failure is worse than a warning the
	// accept loop's own attaches can still recover from.
	return PreflightResult{Outcome: PreflightWarn, Msg: err.Error()}
}
