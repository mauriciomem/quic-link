package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
)

// newConnectCmd returns the connect command as a hidden deprecated alias for
// "daemon --server NAME". Any new work should use the daemon verb instead.
//
// connect SERVER is equivalent to daemon --server SERVER.
//
// With no SERVER argument and exactly one enabled server in the config, that
// server is used automatically. With no argument and more than one enabled
// server, exit 2 tells the user to name one or use "daemon".
func newConnectCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "connect [SERVER]",
		Hidden: true, // deprecated alias; does not appear in help listings
		Short:  "[DEPRECATED] Use 'daemon --server NAME' instead",
		Long: `connect is a deprecated alias for 'daemon --server SERVER'.

It will be removed in a future release. Use 'daemon --server NAME' for the
same behaviour. With no SERVER argument and exactly one enabled server in the
config, that server is used automatically.`,
		Args: wrapArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Print a deprecation warning to stderr. It must go to stderr so it
			// does not pollute stdout contracts (scp/ssh byte streams etc.).
			fmt.Fprintln(cmd.ErrOrStderr(),
				"warning: 'connect' is deprecated and will be removed; use 'daemon --server NAME' instead")

			scope, err := resolveConnectScope(a.cfg, a.configPath, args)
			if err != nil {
				return err
			}

			return runDaemonOwner(cmd, a.cfg, scope, a.configPath)
		},
	}
	return cmd
}

// resolveConnectScope maps the connect command's optional positional argument
// to a server name for runDaemonOwner.
//
// Rules:
//   - One argument given: use it as the server name (runDaemonOwner validates
//     it against the config and rejects missing/disabled entries).
//   - No argument, exactly one enabled server: use that server automatically.
//   - No argument, more than one enabled server: exit 2 — the user must name one.
//   - No argument, no enabled servers: exit 2.
func resolveConnectScope(cfg *config.Config, configPath string, args []string) (string, error) {
	if len(args) == 1 {
		// Positional arg given: pass through to runDaemonOwner which validates it.
		return args[0], nil
	}

	// No argument: auto-select from enabled servers. connect is a settings-only
	// owner verb by design (see newConnectCmd's doc comment) — it never asks a
	// running daemon the way autoSelectServer does, so its wording says "in
	// your settings" unconditionally rather than branching on where the
	// answer came from.
	enabled := enabledServers(cfg.Servers)
	switch len(enabled) {
	case 0:
		return "", usageErrorf(
			"no SERVER given and no enabled servers in your settings; add a "+
				"[servers.<name>] entry to %s, or use 'daemon' with server flags",
			config.FileInUse(configPath))
	case 1:
		// Exactly one server: return it. The loop runs exactly once;
		// the return inside the loop is always reached.
		for name := range enabled {
			return name, nil
		}
	default:
		return "", usageErrorf(
			"no SERVER given and %d servers are enabled in your settings; "+
				"specify one: connect SERVER, or use: daemon --server NAME\n"+
				"  available: %s",
			len(enabled), serverNameList(enabled))
	}
	// This line is unreachable: the switch above covers all possible values
	// of len(enabled) (0, 1, and >1 via default), and every branch either
	// returns directly or falls through to here only from case 1 — but case 1
	// always returns inside the for loop. The compiler requires a return
	// statement here because it cannot prove the for loop body executes.
	panic("unreachable: enabled map with len=1 had no entries")
}

// enabledServers returns the subset of servers for which enabled is nil or true.
func enabledServers(servers map[string]config.Server) map[string]config.Server {
	out := make(map[string]config.Server)
	for name, srv := range servers {
		if srv.Enabled == nil || *srv.Enabled {
			out[name] = srv
		}
	}
	return out
}

// serverNameList returns a comma-separated, sorted list of server names for
// error messages.
func serverNameList(servers map[string]config.Server) string {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
