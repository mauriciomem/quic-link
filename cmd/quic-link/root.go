package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// newRootCmd builds and returns the root cobra.Command. All subcommands are
// registered here. Global persistent flags (--config, --log-level) are defined
// on the root and inherited by every subcommand.
func newRootCmd() *cobra.Command {
	var (
		configPath string
		logLevel   string
	)

	root := &cobra.Command{
		Use:   "quic-link",
		Short: "Minimal QUIC tunnel with mutual Ed25519 pin authentication",
		Long: `quic-link is a QUIC tunnel that multiplexes SSH and Docker streams over one
mutually-authenticated connection. Authentication is mandatory: each end holds an
Ed25519 key, exchanges pins out of band, and verifies the peer's pin during the
TLS handshake. There are no CA files.

Pairing (one time per host):
  quic-link keygen                          # prints "pin: <base64>"
  # exchange the two pins out of band, then use them with agent/connect below.

Examples:
  # Agent (remote, UDP port 443 must be reachable)
  quic-link agent --listen :443 --service-addr 127.0.0.1:22 \
      --authorized-client <client-pin>

  # Client (local — then: ssh -p 2222 user@127.0.0.1)
  quic-link connect --server myserver.example.com:443 --local 127.0.0.1:2222 \
      --pin <agent-pin>

  # Ping
  quic-link ping --server myserver.example.com:443 --pin <agent-pin>`,

		// SilenceErrors prevents cobra from printing the error itself;
		// main() logs it with slog and maps it to the correct exit code.
		SilenceErrors: true,

		// SilenceUsage prevents cobra from automatically printing the full
		// usage block when any RunE returns an error. Verbs that detect a
		// usage error print usage manually before returning, preserving the
		// historical "missing required flag shows usage + exit 2" behaviour.
		SilenceUsage: true,

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Set up structured logging at the requested level.
			level, err := parseLogLevel(logLevel)
			if err != nil {
				return err
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: level,
			})))

			// TODO: load --config file here when config-file support lands.
			// Parsed values should be merged under the flag > env > file >
			// default precedence order.
			_ = configPath

			return nil
		},
	}

	// Global flags available to every subcommand.
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config file (optional)")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log verbosity: debug, info, warn, or error")

	// Register subcommands.
	root.AddCommand(
		newKeygenCmd(),
		newAgentCmd(),
		newConnectCmd(),
		newPingCmd(),
		newStdioCmd(),
	)

	return root
}

// parseLogLevel converts a level name to the corresponding slog.Level.
// Unknown names are returned as a usage error so main() exits 2 and the
// operator sees the valid options rather than an opaque failure.
func parseLogLevel(name string) (slog.Level, error) {
	switch name {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, usageErrorf("unknown --log-level %q: must be debug, info, warn, or error", name)
	}
}

// executeRoot wires the signal-notified context into the root command and runs
// it.  It is called by main; extracted here so tests can call it too.
func executeRoot(ctx context.Context, args []string) error {
	root := newRootCmd()
	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}
