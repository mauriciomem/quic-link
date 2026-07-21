package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	var (
		listen      string
		serviceAddr string
		dockerAddr  string
		keyFile     string
		authorized  pinList
	)

	cmd := &cobra.Command{
		Use:     "agent",
		Aliases: []string{"serve"},
		Short:   "Run the QUIC agent endpoint (accepts tunnelled connections)",
		Long: `Run the QUIC agent (server-side) endpoint. It binds a UDP port, performs
mutual Ed25519 pin authentication with every connecting client, and forwards
accepted streams to the configured local services.

At least one --authorized-client pin is required: the agent never accepts
unauthenticated connections.

The name "serve" is a deprecated alias for "agent" and will be removed in a
future release. Use "agent" in new deployments.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(authorized) == 0 {
				// Print usage to stderr before returning, matching historical
				// behaviour where the operator sees the flag list alongside the
				// error message.
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("at least one --authorized-client pin is required")
			}
			return agentRun(cmd.Context(), listen, serviceAddr, dockerAddr, keyFile, authorized)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":443", "UDP address to listen on")
	cmd.Flags().StringVar(&serviceAddr, "service-addr", "127.0.0.1:22", "TCP address of the ssh service (host:port)")
	cmd.Flags().StringVar(&dockerAddr, "docker-addr", "unix:///var/run/docker.sock", "docker daemon address (unix:///path or tcp://host:port)")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().Var(&authorized, "authorized-client", "authorized client pin (repeatable; at least one required)")

	return cmd
}

// agentRun is the implementation of the agent verb.  It is separate from the
// cobra RunE so the logic can be read without constructing a cobra.Command.
func agentRun(ctx context.Context, listen, serviceAddr, dockerAddr, keyFile string, authorized pinList) error {
	// Authentication (the pin handshake) is enforced at the TLS layer; route-
	// table authorisation is allow-all with an injectable deny policy.
	key, err := identity.LoadKey(expandTilde(keyFile))
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}
	tlsConf, err := identity.ServerTLS(key, authorized)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	rtr, err := router.New(map[string]string{
		"ssh":    "tcp://" + serviceAddr,
		"docker": dockerAddr,
	}, router.AllowAll{})
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("invalid --listen address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind %s: %w", listen, err)
	}
	defer udpConn.Close()

	t, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer t.Close()

	ln, err := t.Listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	// Log only the count of authorised clients, never the pin values.
	slog.Info("quic-link agent ready",
		"listen", ln.Addr(),
		"targets", rtr.Targets(),
		"authorized_clients", len(authorized),
	)
	return tunnel.Serve(ctx, ln, rtr)
}
