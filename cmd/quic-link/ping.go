package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/transport"
)

func newPingCmd(a *app) *cobra.Command {
	var (
		serverFlag string
		count      int
		keyFile    string
		pin        string
	)

	cmd := &cobra.Command{
		Use:   "ping [SERVER]",
		Short: "Measure QUIC handshake time and RTT to an agent",
		Long: `Send one or more probe connections to a quic-link agent and report
transport RTT statistics and control-stream RPC round-trip time.

Each probe opens a fresh QUIC connection so the handshake cost is measured
independently. SERVER is the name of a server defined in the config file; if
omitted and exactly one enabled server exists, it is used automatically.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()

			// --- resolve the effective server config --------------------

			srv := config.Server{}
			serverName := ""

			if len(args) == 1 {
				serverName = args[0]
				named, ok := a.cfg.Servers[serverName]
				if !ok {
					fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
					return usageErrorf("server %q not found in config", serverName)
				}
				srv = named
			} else if flags.Changed("server") {
				serverName = ""
			} else {
				enabled := enabledServers(a.cfg.Servers)
				switch len(enabled) {
				case 1:
					for name, s := range enabled {
						serverName = name
						srv = s
					}
				case 0:
					fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
					return usageErrorf("no SERVER given and no enabled servers in config; use --server or add a [servers.<name>] entry")
				default:
					fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
					return usageErrorf("no SERVER given and %d enabled servers in config; specify one: %s",
						len(enabled), serverNameList(enabled))
				}
			}

			// --- overlay Changed flags ----------------------------------

			if flags.Changed("server") {
				srv.Addr = serverFlag
				srv.Listen = ""
			}
			if flags.Changed("pin") {
				srv.Pin = pin
			}
			if flags.Changed("key") {
				a.cfg.Identity.KeyFile = keyFile
			}

			// --- enabled check ------------------------------------------

			if srv.Enabled != nil && !*srv.Enabled {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("server %q is disabled; set enabled = true in the config to use it", serverName)
			}

			// --- reverse-mode guard ------------------------------------

			if srv.Listen != "" && srv.Addr == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("reverse mode (listen) is not yet supported; it runs in a later phase")
			}

			if srv.Addr == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("--server is required (or specify a SERVER name with an addr in the config)")
			}

			// --- pin validation ----------------------------------------

			serverPin, err := identity.ParsePin(srv.Pin)
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("pin is required and must be a valid pin: %v", err)
			}

			// --- validate the effective config -------------------------
			// Register the resolved server (with flag overrides applied) so
			// Validate checks the effective server this run will use.
			regKey := serverName
			if regKey == "" {
				regKey = "(flags)"
			}
			if a.cfg.Servers == nil {
				a.cfg.Servers = map[string]config.Server{}
			}
			a.cfg.Servers[regKey] = srv

			warnings, err := a.cfg.Validate(config.RoleClient)
			for _, w := range warnings {
				slog.Warn(w)
			}
			if err != nil {
				return err
			}

			// --- run ---------------------------------------------------

			effectiveKey := a.cfg.Identity.KeyFile
			if flags.Changed("key") {
				effectiveKey = keyFile
			}

			return pingRun(cmd.Context(), srv.Addr, count, effectiveKey, serverPin)
		},
	}

	cmd.Flags().StringVar(&serverFlag, "server", "", "host:port of the quic-link agent (overrides config)")
	cmd.Flags().IntVar(&count, "count", 3, "number of probes to send")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().StringVar(&pin, "pin", "", "expected agent pin (base64; from `quic-link keygen` on the agent)")

	return cmd
}

// aggregateProbeError returns the error to report when every probe failed.
// Auth failures take precedence over unreachability (auth is the more specific
// and actionable diagnosis), which takes precedence over a generic failure.
// When no probe failed for either classified reason the returned error wraps
// neither sentinel.
func aggregateProbeError(count int, authErr, unreachErr error) error {
	switch {
	case authErr != nil:
		return fmt.Errorf("all %d probes failed: %w", count, authErr)
	case unreachErr != nil:
		return fmt.Errorf("all %d probes failed: %w", count, unreachErr)
	default:
		return fmt.Errorf("all %d probes failed", count)
	}
}

// pingRun is the implementation of the ping verb.
func pingRun(ctx context.Context, server string, count int, keyFile, serverPin string) error {
	tlsConf, err := clientTLSFromFlags(keyFile, serverPin)
	if err != nil {
		return err
	}

	var (
		successful     int
		totalHandshake float64
		successfulRTT  int // probes with a genuine transport RTT measurement
		totalSmoothed  float64
		totalMin       float64
		successfulRPC  int
		totalRPC       float64
		authErr        error // set if any probe failed the pin handshake
		unreachErr     error // set if any probe could not reach the agent
	)

	for i := 1; i <= count; i++ {
		// Each probe uses a fresh QUIC connection on a new udp4 socket.
		// udp4 (not dual-stack [::]) so on-link LAN peers are reachable on macOS.
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return fmt.Errorf("UDP socket: %w", err)
		}

		t, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
		if err != nil {
			udpConn.Close()
			return fmt.Errorf("transport: %w", err)
		}

		res, err := probe.Ping(ctx, t, server)
		t.Close()
		udpConn.Close()

		if err != nil {
			if errors.Is(err, transport.ErrAuthFailed) {
				authErr = err
			} else if errors.Is(err, transport.ErrUnreachable) {
				unreachErr = err
			}
			fmt.Fprintf(os.Stderr, "probe %d/%d: %v\n", i, count, err)
			continue
		}

		// Format transport RTT: when HasRTT is false the QUIC implementation has
		// not yet taken a genuine ACK-based sample and the values are a seeded
		// placeholder. Printing "n/a" avoids presenting fabricated numbers as
		// measurements; prose format is intentionally not a contract.
		if res.HasRTT {
			fmt.Printf("probe %d/%d: handshake=%v [measured] smoothed_rtt=%v min_rtt=%v latest_rtt=%v\n",
				i, count,
				res.HandshakeTime.Round(time.Microsecond),
				res.SmoothedRTT.Round(time.Microsecond),
				res.MinRTT.Round(time.Microsecond),
				res.LatestRTT.Round(time.Microsecond),
			)
		} else {
			fmt.Printf("probe %d/%d: handshake=%v [transport RTT: n/a — no ACK sample yet]\n",
				i, count,
				res.HandshakeTime.Round(time.Microsecond),
			)
		}
		// Application-level control-stream RPC round-trip, labelled distinctly
		// from the transport RTT. A control failure is non-fatal: the transport
		// numbers above are still meaningful.
		if res.RPCErr != nil {
			fmt.Printf("           control_rpc: FAILED (%v)\n", res.RPCErr)
		} else {
			fmt.Printf("           control_rpc_rtt=%v\n", res.RPCRoundTrip.Round(time.Microsecond))
			// Surface an invariant violation loudly. This does not change the
			// exit code — it is purely a diagnostic warning for the operator.
			if res.RPCInvariantViolation != nil {
				fmt.Printf("           WARNING: %v\n", res.RPCInvariantViolation)
			}
			totalRPC += float64(res.RPCRoundTrip)
			successfulRPC++
		}
		successful++
		totalHandshake += float64(res.HandshakeTime)
		if res.HasRTT {
			successfulRTT++
			totalSmoothed += float64(res.SmoothedRTT)
			totalMin += float64(res.MinRTT)
		}
	}

	if successful == 0 {
		return aggregateProbeError(count, authErr, unreachErr)
	}
	n := float64(successful)
	fmt.Printf("--- %s ping statistics ---\n", server)
	fmt.Printf("%d probes sent, %d successful\n", count, successful)
	if successfulRTT > 0 {
		fmt.Printf("avg: handshake=%v smoothed_rtt=%v min_rtt=%v (%d/%d measured)\n",
			time.Duration(totalHandshake/n).Round(time.Microsecond),
			time.Duration(totalSmoothed/float64(successfulRTT)).Round(time.Microsecond),
			time.Duration(totalMin/float64(successfulRTT)).Round(time.Microsecond),
			successfulRTT, successful,
		)
	} else {
		fmt.Printf("avg: handshake=%v [transport RTT: n/a — no ACK samples in any probe]\n",
			time.Duration(totalHandshake/n).Round(time.Microsecond),
		)
	}
	if successfulRPC > 0 {
		fmt.Printf("avg: control_rpc_rtt=%v (%d/%d ok)\n",
			time.Duration(totalRPC/float64(successfulRPC)).Round(time.Microsecond),
			successfulRPC, successful,
		)
	}
	return nil
}
