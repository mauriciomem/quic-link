package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

func newAgentCmd(a *app) *cobra.Command {
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

Agent settings may come from [agent] in the config file; flags always win
when both are present.

The name "serve" is a deprecated alias for "agent" and will be removed in a
future release. Use "agent" in new deployments.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()

			// --- build the effective agent config ----------------------
			// If the config file has an [agent] block, start from it.
			// If any agent flag was changed, allocate an Agent struct so
			// flag-only invocations work with no config file at all.
			agentCfg := a.cfg.Agent
			if agentCfg == nil {
				// Only allocate if at least one agent flag was set; otherwise
				// leave nil so Validate can report the block is missing.
				if flags.Changed("listen") || flags.Changed("service-addr") ||
					flags.Changed("docker-addr") || flags.Changed("key") ||
					flags.Changed("authorized-client") {
					agentCfg = &config.Agent{}
				}
			}

			// Overlay flags that were explicitly set. A nil agentCfg here
			// means no config block and no flags → Validate will catch it.
			if agentCfg != nil {
				if flags.Changed("listen") {
					agentCfg.Listen = listen
				}
				if flags.Changed("authorized-client") {
					// Flags fully replace the file's authorized_clients list
					// so there is no accidental merging of stale pins.
					agentCfg.AuthorizedClients = []string(authorized)
				}
				if flags.Changed("service-addr") {
					if agentCfg.Routes == nil {
						agentCfg.Routes = make(map[string]string)
					}
					agentCfg.Routes["ssh"] = "tcp://" + serviceAddr
				}
				if flags.Changed("docker-addr") {
					if agentCfg.Routes == nil {
						agentCfg.Routes = make(map[string]string)
					}
					agentCfg.Routes["docker"] = dockerAddr
				}
				if flags.Changed("key") {
					a.cfg.Identity.KeyFile = keyFile
				}

				// Apply the default listen address when neither the file nor
				// a flag provided one, so Validate sees a sensible value.
				if agentCfg.Listen == "" && agentCfg.Dial == "" {
					agentCfg.Listen = ":443"
				}
			}

			// Write back so Validate operates on the merged view.
			a.cfg.Agent = agentCfg

			// --- reverse-mode guard ------------------------------------
			// Reverse mode (agent dials out) is not yet implemented.
			if agentCfg != nil && agentCfg.Dial != "" && agentCfg.Listen == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("reverse mode (dial) is not yet supported; it runs in a later phase")
			}

			// --- validate the effective config -------------------------
			// authorized_clients empty is always a hard error under RoleAgent
			// regardless of how the config was assembled; Validate enforces it.
			warnings, err := a.cfg.Validate(config.RoleAgent)
			for _, w := range warnings {
				slog.Warn(w)
			}
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return err
			}

			// --- run ---------------------------------------------------
			effectiveKey := a.cfg.Identity.KeyFile
			if flags.Changed("key") {
				effectiveKey = keyFile
			}

			effectiveListen := agentCfg.Listen
			effectiveClients := pinList(agentCfg.AuthorizedClients)
			effectiveRoutes := agentCfg.Routes

			return agentRun(cmd.Context(), effectiveListen, effectiveRoutes, effectiveKey, effectiveClients, a.cfg.Identity)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "", "UDP address to listen on (default :443)")
	cmd.Flags().StringVar(&serviceAddr, "service-addr", "127.0.0.1:22", "TCP address of the ssh service (host:port)")
	cmd.Flags().StringVar(&dockerAddr, "docker-addr", "unix:///var/run/docker.sock", "docker daemon address (unix:///path or tcp://host:port)")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().Var(&authorized, "authorized-client", "authorized client pin (repeatable; at least one required)")

	return cmd
}

// agentRun is the implementation of the agent verb.  It is separate from the
// cobra RunE so the logic can be read without constructing a cobra.Command.
// routes is the full set of route overrides to hand to the router; it is
// merged over the router's built-in ssh and docker defaults. idCfg carries the
// key-age hygiene settings from the identity config block.
func agentRun(ctx context.Context, listen string, routes map[string]string, keyFile string, authorized pinList, idCfg config.Identity) error {
	// Check the age of the local identity key before binding any network
	// resources. An absent .meta file means the key age is unknown — we
	// silently skip the check rather than treating the absence as an alarm.
	if err := checkKeyAge(expandTilde(keyFile), idCfg); err != nil {
		return err
	}

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

	rtr, err := router.New(routes, router.AllowAll{})
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
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
	return tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{WarnKeyAgeDays: idCfg.WarnKeyAgeDays})
}

// checkKeyAge reads the key's .meta sidecar and warns (or refuses) when the
// key is older than the configured threshold. An absent sidecar is silently
// ignored — unknown age is not an alarm.
func checkKeyAge(keyFile string, idCfg config.Identity) error {
	if idCfg.WarnKeyAgeDays <= 0 {
		return nil // threshold disabled; nothing to check
	}
	created, present, err := identity.ReadMeta(keyFile)
	if err != nil {
		// A malformed .meta is unusual but not fatal — log and continue.
		slog.Warn("could not read key metadata; skipping age check",
			"key_file", keyFile, "err", err,
		)
		return nil
	}
	if !present {
		return nil // age unknown; no warning
	}
	ageDays := int(time.Since(created).Hours() / 24)
	if ageDays <= idCfg.WarnKeyAgeDays {
		return nil // key is within the acceptable window
	}
	slog.Warn("identity key is older than the rotation threshold; consider running 'quic-link keygen --force'",
		"key_file", keyFile,
		"key_age_days", ageDays,
		"warn_key_age_days", idCfg.WarnKeyAgeDays,
	)
	if idCfg.RefuseOldKey {
		return usageErrorf("identity key %s is %d days old (threshold %d); set refuse_old_key=false or rotate with 'keygen --force'",
			keyFile, ageDays, idCfg.WarnKeyAgeDays)
	}
	return nil
}
