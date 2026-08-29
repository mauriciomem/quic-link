package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/fwd"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/router"
)

// errDaemonNotRunning is returned when fwd's startup preflight finds no
// daemon listening on the socket (or one speaking a stale schema). Reusing
// errFinalExitCode's "attach refused" wording here would be misleading: no
// attach was ever attempted, because no daemon was ever reached, so nothing
// was refused. This is the same defect class errExecExitCode already exists
// to avoid for ssh's own child-process exit code.
type errDaemonNotRunning struct {
	msg string
}

func (e *errDaemonNotRunning) Error() string {
	return fmt.Sprintf("daemon not running: %s", e.msg)
}

// alreadyReported signals that the remedy ("start it with: quic-link
// daemon") was already written to stderr by runFwd, so main() must not
// print an additional slog.Error line.
func (e *errDaemonNotRunning) alreadyReported() bool { return true }

func newFwdCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fwd [SERVER] TARGET[:LOCAL_PORT]",
		Short: "Ad-hoc local forward to a route-table target",
		Long: `Forward a local TCP port to an existing route-table target on the agent.

TARGET is always a route-table name — never an address, never a port. The
far-side (host, port) pair is fixed on the agent by its route table and is
never client-specifiable: letting the client name a far-side port would turn
a route into a port-scanning primitive, not a fixed service.

LOCAL_PORT, when given, is the LOCAL port fwd binds on 127.0.0.1; when
omitted, a free local port is picked automatically. Prints (CONTRACT):

  listening 127.0.0.1:<port> -> <server>:<target>

Runs in the foreground until Ctrl-C, which resets every open forward
immediately.

fwd requires a running daemon (quic-link daemon); unlike stdio and ssh, it
has no direct-QUIC fallback, since a fresh QUIC/TLS/pin handshake for every
accepted local connection would defeat session pooling entirely.

With no SERVER, the sole enabled server in the config is used automatically
(error 2 if the config has more than one).`,
		// No Args validator: runFwd parses args itself, matching ssh.go's
		// splitSSHArgs precedent — the shape (one optional leading token, one
		// required trailing token) does not fit a canned cobra validator.
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFwd(cmd, a, args)
		},
	}
	return cmd
}

// splitFwdArgs separates fwd's own optional SERVER positional from the
// required trailing TARGET[:LOCAL_PORT].
func splitFwdArgs(args []string) (serverArg, targetArg string, err error) {
	switch len(args) {
	case 1:
		return "", args[0], nil
	case 2:
		return args[0], args[1], nil
	case 0:
		return "", "", usageErrorf("TARGET is required: fwd [SERVER] TARGET[:LOCAL_PORT]")
	default:
		return "", "", usageErrorf("too many arguments: fwd [SERVER] TARGET[:LOCAL_PORT]")
	}
}

// parseFwdTarget splits TARGET[:LOCAL_PORT] on the FIRST colon — route names
// cannot contain one (internal/router.ValidateRouteName enforces this for
// every route name regardless of source), so the split is unambiguous. A
// present LOCAL_PORT must be an integer from 1 to 65535; 0 is rejected
// rather than treated as a synonym for the auto-pick you get by omitting the
// suffix entirely, so a typo ":0" does not silently behave like leaving the
// suffix off.
//
// TARGET is validated locally with the same router.ValidateRouteName rule
// the agent applies to every route name regardless of source. The agent is
// still the authoritative boundary — it would reject a bad name on its own
// — but validating here too means a typo (a stray '/', a control byte) fails
// fast with a clear local usage error instead of surfacing as a remote
// bad-header failure the operator has to go dig for.
func parseFwdTarget(arg string) (target string, port int, err error) {
	target, portStr, found := strings.Cut(arg, ":")
	if verr := router.ValidateRouteName(target); verr != nil {
		return "", 0, usageErrorf("invalid TARGET %q: %v", target, verr)
	}
	if !found {
		return target, 0, nil
	}
	n, perr := strconv.Atoi(portStr)
	if perr != nil {
		return "", 0, usageErrorf("invalid LOCAL_PORT %q: must be an integer from 1 to 65535", portStr)
	}
	if n < 1 || n > 65535 {
		return "", 0, usageErrorf("invalid LOCAL_PORT %d: must be an integer from 1 to 65535", n)
	}
	return target, n, nil
}

// bindFwdListener binds the local listener per the bind-and-hold rule: never
// probe-then-close-then-rebind. port == 0 means "auto-pick" — bind
// 127.0.0.1:0 and read the assigned port back from the listener's own
// Addr(), the same two-line pattern already used at daemoncmd.go's own port
// acquisition — rather than closing a probe listener and reopening on the
// discovered port, which would reopen the exact TOCTOU already removed from
// the daemon's own local-port path.
func bindFwdListener(port int) (net.Listener, int, error) {
	addr := "127.0.0.1:0"
	if port > 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, 0, classifyBindError(port, err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

// classifyBindError maps a bind failure to a usage error with a message
// naming the specific remedy, using errors.Is against the underlying syscall
// errno rather than matching on the error's string form — the project has a
// recorded lesson about exactly that mistake (a string-matching bug in an
// earlier socket-reclaim check was found in security review and replaced
// with errors.Is).
func classifyBindError(port int, err error) error {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return usageErrorf(
			"local port %d is already in use; choose a different LOCAL_PORT or omit it to auto-pick one",
			port)
	case errors.Is(err, syscall.EACCES):
		// Deliberately does not suggest running quic-link with elevated
		// privileges: quic-link never escalates at runtime and has no
		// runtime-privilege model at all, and an opaque permission error
		// that nudges a frustrated user toward running the whole binary
		// with more privilege than it needs would put the long-lived
		// Ed25519 identity key in a needlessly over-privileged process.
		return usageErrorf(
			"local port %d requires elevated privileges to bind; choose a local port of 1024 or above instead",
			port)
	default:
		return fmt.Errorf("bind local port: %w", err)
	}
}

// runFwd implements the fwd verb: resolve SERVER/TARGET/LOCAL_PORT, run the
// startup preflight attach, bind the local port, print the CONTRACT line,
// and run internal/fwd's accept loop in the foreground until the command's
// context is cancelled (Ctrl-C).
func runFwd(cmd *cobra.Command, a *app, args []string) error {
	serverArg, targetArg, err := splitFwdArgs(args)
	if err != nil {
		return err
	}
	target, port, err := parseFwdTarget(targetArg)
	if err != nil {
		return err
	}

	var scopeArgs []string
	if serverArg != "" {
		scopeArgs = []string{serverArg}
	}
	server, err := autoSelectServer(a, scopeArgs)
	if err != nil {
		return err
	}
	// An unknown server name must be refused here, before any side effect.
	// Without this check the name reaches the daemon's attach preflight,
	// which answers a bare status 3 for both "unknown server" and "session
	// not ready yet" — the same code the preflight already treats as
	// transient and warns through, so an unknown name fell all the way to
	// bindFwdListener and held a local port open until killed, never
	// refusing at all. Checking the name against knownServers directly, the
	// same way ssh/status/expose/vhosts already do, catches the mistake
	// before a port is ever bound.
	if err := requireKnownServer(a, server); err != nil {
		return err
	}

	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}
	client := ipc.NewClient(sock)

	pre := fwd.Preflight(client, server, target)
	switch pre.Outcome {
	case fwd.PreflightDaemonAbsent:
		fmt.Fprintln(cmd.ErrOrStderr(),
			"daemon is not running; start it with: quic-link daemon")
		return &errDaemonNotRunning{msg: pre.Msg}
	case fwd.PreflightFatal:
		fmt.Fprintf(cmd.ErrOrStderr(), "agent refused: %s\n", pre.Msg)
		if pre.Guidance != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), pre.Guidance)
		}
		return &errFinalExitCode{code: pre.Status, msg: pre.Msg}
	case fwd.PreflightWarn:
		fmt.Fprintf(cmd.ErrOrStderr(),
			"warning: target %q could not be validated yet (%s); listening anyway\n",
			target, pre.Msg)
	}

	ln, boundPort, err := bindFwdListener(port)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "listening 127.0.0.1:%d -> %s:%s\n", boundPort, server, target)

	f := fwd.New(server, target, ln, client, fwd.Options{})
	f.Run(cmd.Context())
	return nil
}
