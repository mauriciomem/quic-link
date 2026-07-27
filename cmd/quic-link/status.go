package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

func newStatusCmd(a *app) *cobra.Command {
	var jsonFlag bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the daemon's current session state",
		Long: `Show the state of all QUIC sessions managed by the running daemon.

If no daemon is running, status exits 3 with a remedy message.
If the daemon is a stale version (socket schema mismatch), status exits 3 with
a restart instruction.

The --json flag prints the frozen machine-readable shape to stdout (CONTRACT):
  {"schema":1,"identity":{"created":"...","age_days":N,"rotation_due":false},
   "servers":[{"name":"...","session":"connected|connecting|listening|disabled",
   "transport":"dial|listen","since_ms":N,"local_ports":{"ssh":N,"docker":N}}]}

The "session" field is an open enum: consumers must tolerate unrecognized values
by treating them as "not healthy / see logs".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "print machine-readable JSON (CONTRACT)")
	return cmd
}
