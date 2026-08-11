package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

func newStatusCmd(a *app) *cobra.Command {
	var jsonFlag bool
	var routesFlag bool

	cmd := &cobra.Command{
		Use:   "status [SERVER]",
		Short: "Show the daemon's current session state",
		Long: `Show the state of all QUIC sessions managed by the running daemon.

If no daemon is running, status exits 3 with a remedy message.
If the daemon is a stale version (socket schema mismatch), status exits 3 with
a restart instruction.

The --json flag prints the frozen machine-readable shape to stdout (CONTRACT):
  {"schema":1,"identity":{"created":"...","age_days":N,"rotation_due":false},
   "servers":[{"name":"...","session":"connected|connecting|listening|disabled|auth_failed",
   "transport":"dial|listen","since_ms":N,"local_ports":{"ssh":N,"docker":N}}]}

The "session" field is an open enum: consumers must tolerate unrecognized values
by treating them as "not healthy / see logs".

--routes additionally asks a named SERVER's agent, live, for its current
route table. This is a real network round trip through the daemon to the
agent, so it is never performed by plain "status" or "status --json" alone —
those two never take SERVER and never leave the daemon's own local
snapshot. SERVER may be omitted with --routes when exactly one server is
enabled in config, the same auto-selection "ssh"/"docker-env"/"connect" use.

Route names and addresses come from the agent, not from this machine: they
are sanitized before being printed or included in --routes --json, since an
authenticated-but-compromised agent could otherwise forge terminal escape
sequences or extra lines in scripted output.`,
		Args: wrapArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if routesFlag {
				return runStatusRoutes(cmd, a, args, jsonFlag)
			}
			if len(args) > 0 {
				return usageErrorf("SERVER argument is only accepted together with --routes")
			}
			return runStatusPlain(cmd, a, jsonFlag)
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "print machine-readable JSON (CONTRACT)")
	cmd.Flags().BoolVar(&routesFlag, "routes", false, "show SERVER's live route table (issues a network call to the agent)")
	return cmd
}

// runStatusPlain is the pre-existing "status [--json]" behaviour, unchanged:
// one local read of the daemon's own snapshot, no positional argument, and
// no call to any RoutesProvider. Extracted unmodified from newStatusCmd's
// RunE so --routes can share the command without altering this path's
// bytes, latency, or code path in any way.
func runStatusPlain(cmd *cobra.Command, a *app, jsonFlag bool) error {
	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}

	c := ipc.NewClient(sock)
	raw, err := c.StatusJSON()
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonAbsent) {
			fmt.Fprintln(cmd.ErrOrStderr(),
				"daemon is not running; start it with: quic-link daemon")
			return err
		}
		if errors.Is(err, ipc.ErrSchemaMismatch) {
			fmt.Fprintln(cmd.ErrOrStderr(),
				"daemon is a stale version; restart it with: quic-link daemon")
			return err
		}
		return fmt.Errorf("status: %w", err)
	}

	if jsonFlag {
		// Print the raw JSON bytes exactly as returned by the daemon —
		// no re-encoding so the byte-shape is stable.
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", raw)
		return nil
	}

	// Human-readable output is deliberately free-form (anti-contract).
	fmt.Fprintf(cmd.OutOrStdout(), "%s\n", raw)
	return nil
}

// runStatusRoutes implements "status --routes [SERVER]": resolve SERVER the
// same way connect/ssh/docker-env do, reject a name absent from config
// before ever reaching the daemon, issue the "routes" IPC method (not
// "status"), and render the result through the sanitizing presentation
// layer in routes_sanitize.go. Every failure mode the daemon's own
// routesProvider distinguishes (internal/daemon/routes.go) arrives here as
// an *ipc.RoutesError carrying that provider's own status and message,
// which is printed and mapped to the exit code verbatim — this function
// does not re-derive or re-word any of those messages.
func runStatusRoutes(cmd *cobra.Command, a *app, args []string, jsonFlag bool) error {
	serverName, err := autoSelectServer(a, args)
	if err != nil {
		return err
	}
	if err := requireKnownServer(a, serverName); err != nil {
		return err
	}

	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}

	raw, err := ipc.NewClient(sock).RoutesJSON(serverName)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonAbsent) {
			fmt.Fprintln(cmd.ErrOrStderr(),
				"daemon is not running; start it with: quic-link daemon")
			return err
		}
		if errors.Is(err, ipc.ErrSchemaMismatch) {
			fmt.Fprintln(cmd.ErrOrStderr(),
				"daemon is a stale version; restart it with: quic-link daemon")
			return err
		}
		var re *ipc.RoutesError
		if errors.As(err, &re) {
			// The daemon's routesProvider already picked the exact,
			// distinguishable message and status for this failure — relay
			// both verbatim, matching the taxonomy documented in
			// internal/daemon/routes.go rather than re-wording it here.
			fmt.Fprintln(cmd.ErrOrStderr(), re.Msg)
			return &errFinalExitCode{code: int(re.Status), msg: re.Msg}
		}
		return fmt.Errorf("routes: %w", err)
	}

	var snap daemon.RoutesSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("parse routes response: %w", err)
	}

	// Every agent-controlled field is sanitized here, once, before either
	// rendering path below sees it — see routes_sanitize.go for what that
	// means and why both the human and --json paths get it.
	routes := sanitizeRoutes(snap.Routes)

	if jsonFlag {
		out := routesJSONOutput{Schema: snap.Schema, Server: snap.Server, Routes: routes}
		b, merr := json.Marshal(out)
		if merr != nil {
			return fmt.Errorf("marshal routes output: %w", merr)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", b)
		return nil
	}

	printRoutesHuman(cmd.OutOrStdout(), snap.Server, routes)
	return nil
}
