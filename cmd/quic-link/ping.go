package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/spf13/cobra"
)

func newPingCmd() *cobra.Command {
	var (
		server  string
		count   int
		keyFile string
		pin     string
	)

	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Measure QUIC handshake time and RTT to an agent",
		Long: `Send one or more probe connections to a quic-link agent and report
transport RTT statistics and control-stream RPC round-trip time.

Each probe opens a fresh QUIC connection so the handshake cost is measured
independently. Both --server and --pin are required.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if server == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("--server is required")
			}
			serverPin, err := identity.ParsePin(pin)
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("--pin is required and must be a valid pin: %v", err)
			}
			return pingRun(cmd.Context(), server, count, keyFile, serverPin)
		},
	}

	cmd.Flags().StringVar(&server, "server", "", "host:port of the quic-link agent")
	cmd.Flags().IntVar(&count, "count", 3, "number of probes to send")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().StringVar(&pin, "pin", "", "expected agent pin (base64; from `quic-link keygen` on the agent)")

	return cmd
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
		totalSmoothed  float64
		totalMin       float64
		successfulRPC  int
		totalRPC       float64
		authErr        error // set if any probe failed the pin handshake
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
			}
			fmt.Fprintf(os.Stderr, "probe %d/%d: %v\n", i, count, err)
			continue
		}

		fmt.Printf("probe %d/%d: handshake=%v smoothed_rtt=%v min_rtt=%v latest_rtt=%v\n",
			i, count,
			res.HandshakeTime.Round(time.Microsecond),
			res.SmoothedRTT.Round(time.Microsecond),
			res.MinRTT.Round(time.Microsecond),
			res.LatestRTT.Round(time.Microsecond),
		)
		// Application-level control-stream RPC round-trip, labelled distinctly
		// from the transport RTT. A control failure is non-fatal: the transport
		// numbers above are still meaningful.
		if res.RPCErr != nil {
			fmt.Printf("           control_rpc: FAILED (%v)\n", res.RPCErr)
		} else {
			fmt.Printf("           control_rpc_rtt=%v\n", res.RPCRoundTrip.Round(time.Microsecond))
			totalRPC += float64(res.RPCRoundTrip)
			successfulRPC++
		}
		successful++
		totalHandshake += float64(res.HandshakeTime)
		totalSmoothed += float64(res.SmoothedRTT)
		totalMin += float64(res.MinRTT)
	}

	if successful == 0 {
		// If every probe failed the pin handshake, surface it as an auth error
		// so main() exits 4 rather than collapsing to the generic exit 1.
		if authErr != nil {
			return fmt.Errorf("all %d probes failed: %w", count, authErr)
		}
		return fmt.Errorf("all %d probes failed", count)
	}
	n := float64(successful)
	fmt.Printf("--- %s ping statistics ---\n", server)
	fmt.Printf("%d probes sent, %d successful\n", count, successful)
	fmt.Printf("avg: handshake=%v smoothed_rtt=%v min_rtt=%v\n",
		time.Duration(totalHandshake/n).Round(time.Microsecond),
		time.Duration(totalSmoothed/n).Round(time.Microsecond),
		time.Duration(totalMin/n).Round(time.Microsecond),
	)
	if successfulRPC > 0 {
		fmt.Printf("avg: control_rpc_rtt=%v (%d/%d ok)\n",
			time.Duration(totalRPC/float64(successfulRPC)).Round(time.Microsecond),
			successfulRPC, successful,
		)
	}
	return nil
}
