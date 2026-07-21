package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	var (
		server      string
		local       string
		localDocker string
		sshTarget   string
		keyFile     string
		pin         string
	)

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Run the local client endpoint, tunnelling traffic to the agent",
		Long: `Run the local client endpoint. It connects to a quic-link agent over QUIC,
authenticates via mutual Ed25519 pin exchange, then listens on local TCP ports
and forwards connections through the tunnel to the named targets on the agent.

Both --server and --pin are required.`,
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
			return connectRun(cmd.Context(), server, local, localDocker, sshTarget, keyFile, serverPin)
		},
	}

	cmd.Flags().StringVar(&server, "server", "", "host:port of the quic-link agent")
	cmd.Flags().StringVar(&local, "local", "127.0.0.1:2222", "local TCP address for the ssh target")
	cmd.Flags().StringVar(&localDocker, "local-docker", "127.0.0.1:2375", "local TCP address for the docker target")
	cmd.Flags().StringVar(&sshTarget, "ssh-target", "ssh", "logical target for --local (advanced; for unknown-target checks)")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().StringVar(&pin, "pin", "", "expected agent pin (base64; from `quic-link keygen` on the agent)")

	return cmd
}

// connectRun is the implementation of the connect verb.
func connectRun(ctx context.Context, server, local, localDocker, sshTarget, keyFile, serverPin string) error {
	tlsConf, err := clientTLSFromFlags(keyFile, serverPin)
	if err != nil {
		return err
	}

	// Bind a udp4 (not dual-stack [::]) socket for outbound QUIC. On macOS a
	// dual-stack socket fails to transmit IPv4-mapped datagrams to on-link
	// neighbors because no ARP is performed, silently dropping LAN traffic.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("UDP socket: %w", err)
	}
	defer udpConn.Close()

	t, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer t.Close()

	sshLn, err := net.Listen("tcp", local)
	if err != nil {
		return fmt.Errorf("bind ssh port %s: %w", local, err)
	}
	defer sshLn.Close()

	dockerLn, err := net.Listen("tcp", localDocker)
	if err != nil {
		return fmt.Errorf("bind docker port %s: %w", localDocker, err)
	}
	defer dockerLn.Close()

	slog.Info("quic-link connect ready",
		"ssh_local", sshLn.Addr(),
		"docker_local", dockerLn.Addr(),
		"server", server,
	)
	forwards := []tunnel.Forward{
		{Listener: sshLn, Target: sshTarget},
		{Listener: dockerLn, Target: "docker"},
	}
	return tunnel.Connect(ctx, t, server, forwards)
}
