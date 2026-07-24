package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
)

// app is a shared holder passed to every verb constructor so that
// PersistentPreRunE can load the config once and all subcommands can read it.
// Flags are stored here too so their Changed state is readable in
// PersistentPreRunE before any subcommand RunE runs.
type app struct {
	configPath string
	logLevel   string
	cfg        *config.Config
}

// newRootCmd builds and returns the root cobra.Command. All subcommands are
// registered here. Global persistent flags (--config, --log-level) are defined
// on the root and inherited by every subcommand.
func newRootCmd() *cobra.Command {
	a := &app{}

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
			// Load the config file. An empty configPath means "try the
			// default location; missing is fine." An explicit path that does
			// not exist is an error (wrapped ErrInvalid → exit 2).
			// keygen creates the identity before any config need exist and
			// reads nothing from config, so a missing or malformed config must
			// never block key generation. Every other verb loads config here.
			var cfg *config.Config
			if cmd.Name() == "keygen" {
				cfg = config.Defaults()
			} else {
				loaded, lerr := config.Load(a.configPath)
				if lerr != nil {
					return lerr
				}
				cfg = loaded
			}
			a.cfg = cfg

			// Effective log level: --log-level flag wins over the file/env
			// value, which wins over the built-in default ("info").
			levelStr := cfg.Log.Level // already has file/env/default applied
			if cmd.Root().PersistentFlags().Lookup("log-level").Changed {
				levelStr = a.logLevel
			}
			level, err := parseLogLevel(levelStr)
			if err != nil {
				return err
			}

			// Choose the log output format. "json" → structured JSON;
			// "text" (and the empty default) → human-readable text.
			// Any other value is a configuration error (exit 2).
			format := cfg.Log.Format
			if format == "" {
				format = "text"
			}
			switch format {
			case "text":
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: level,
				})))
			case "json":
				slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
					Level: level,
				})))
			default:
				return usageErrorf("unknown log.format %q: must be text or json", format)
			}

			return nil
		},
	}

	// Global flags available to every subcommand.
	root.PersistentFlags().StringVar(&a.configPath, "config", "", "path to config file (optional)")
	root.PersistentFlags().StringVar(&a.logLevel, "log-level", "info", "log verbosity: debug, info, warn, or error")

	// Register subcommands, passing the shared app so each verb can reach
	// the loaded config after PersistentPreRunE populates a.cfg.
	root.AddCommand(
		newKeygenCmd(),
		newAgentCmd(a),
		newConnectCmd(a),
		newPingCmd(a),
		newStdioCmd(a),
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
		return 0, usageErrorf("unknown log level %q: must be debug, info, warn, or error", name)
	}
}

// executeRoot wires the signal-notified context into the root command and runs
// it.  It is called by main; extracted here so tests can call it too.
func executeRoot(ctx context.Context, args []string) error {
	root := newRootCmd()
	root.SetArgs(args)
	return root.ExecuteContext(ctx)
}
