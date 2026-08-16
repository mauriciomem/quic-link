package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/backoff"
	"github.com/mauriciomem/quic-link/internal/buildinfo"
	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

func newAgentCmd(a *app) *cobra.Command {
	var (
		listen     string
		dial       string
		sshAddr    string
		dockerAddr string
		keyFile    string
		authorized pinList
		routes     routeList
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

			// --- mutual exclusion: --ssh-addr/--docker-addr vs --route ---
			// --ssh-addr and --route ssh=ADDR name the exact same route
			// entry, and so do --docker-addr and --route docker=ADDR. A
			// silent last-wins precedence between two flags that mean the
			// same thing would be a trap the user has no way to see coming,
			// so giving both in one invocation is a usage error.
			if flags.Changed("ssh-addr") {
				if existing, ok := routes.values["ssh"]; ok {
					return usageErrorf("--ssh-addr and --route ssh=%s both set the ssh route; use only one", existing)
				}
			}
			if flags.Changed("docker-addr") {
				if existing, ok := routes.values["docker"]; ok {
					return usageErrorf("--docker-addr and --route docker=%s both set the docker route; use only one", existing)
				}
			}

			// --- build the effective agent config ----------------------
			// If the config file has an [agent] block, start from it.
			// If any agent flag was changed, allocate an Agent struct so
			// flag-only invocations work with no config file at all.
			agentCfg := a.cfg.Agent
			if agentCfg == nil {
				// Only allocate if at least one agent flag was set; otherwise
				// leave nil so Validate can report the block is missing.
				if flags.Changed("listen") || flags.Changed("dial") ||
					flags.Changed("ssh-addr") ||
					flags.Changed("docker-addr") || flags.Changed("route") ||
					flags.Changed("key") || flags.Changed("authorized-client") {
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
				if flags.Changed("ssh-addr") {
					if agentCfg.Routes == nil {
						agentCfg.Routes = make(map[string]string)
					}
					agentCfg.Routes["ssh"] = sshAddr
				}
				if flags.Changed("docker-addr") {
					if agentCfg.Routes == nil {
						agentCfg.Routes = make(map[string]string)
					}
					agentCfg.Routes["docker"] = dockerAddr
				}
				if flags.Changed("route") {
					if agentCfg.Routes == nil {
						agentCfg.Routes = make(map[string]string)
					}
					for name, addr := range routes.values {
						agentCfg.Routes[name] = addr
					}
				}
				if flags.Changed("dial") {
					agentCfg.Dial = dial
					// A dial address and a listen address are two different
					// answers to the same question. Taking the flag means
					// dropping any listen address the file supplied, or
					// validation would reject the merged view for setting both.
					if !flags.Changed("listen") {
						agentCfg.Listen = ""
					}
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

			effectiveClients := pinList(agentCfg.AuthorizedClients)
			effectiveRoutes := agentCfg.Routes
			effectiveVhosts := agentCfg.Vhosts

			effectiveAgent := *agentCfg
			effectiveAgent.Routes = effectiveRoutes
			effectiveAgent.Vhosts = effectiveVhosts
			effectiveAgent.AuthorizedClients = nil // carried separately, already resolved
			return agentRun(cmd.Context(), effectiveAgent, effectiveKey, effectiveClients, a.cfg.Identity)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "", "UDP address to wait for connections on (default :443)")
	cmd.Flags().StringVar(&dial, "dial", "", "UDP address of a client that waits for this agent to connect (mutually exclusive with --listen)")
	cmd.Flags().StringVar(&sshAddr, "ssh-addr", "tcp://127.0.0.1:22", "ssh route address (tcp://host:port)")
	cmd.Flags().StringVar(&dockerAddr, "docker-addr", "unix:///var/run/docker.sock", "docker daemon address (unix:///path or tcp://host:port)")
	cmd.Flags().Var(&routes, "route", "additional route as NAME=ADDR (repeatable; tcp://host:port or unix:///path)")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().Var(&authorized, "authorized-client", "authorized client pin (repeatable; at least one required)")

	return cmd
}

// agentRun is the implementation of the agent verb.  It is separate from the
// cobra RunE so the logic can be read without constructing a cobra.Command.
// routes is the full set of route overrides to hand to the router; it is
// merged over the router's built-in ssh and docker defaults. idCfg carries the
// key-age hygiene settings from the identity config block.
// agentRun runs the agent. It takes the agent's settings as a value rather
// than a pointer: the caller's copy is part of the loaded configuration, and
// nothing below here has any business changing what was loaded.
func agentRun(ctx context.Context, ag config.Agent, keyFile string, authorized pinList, idCfg config.Identity) error {
	listen, dial := ag.Listen, ag.Dial
	routes, vhosts := ag.Routes, ag.Vhosts
	// Captured here, at the top of the function that does the agent's real
	// work, rather than in main() or an init(): this is the closest thing
	// the tree has to a tracked "agent process start time" today, and
	// adding a new package-level global just to shave a few milliseconds
	// off the timestamp (config parsing, flag validation) would be
	// speculative precision nobody asked for. GetStatus reports this
	// verbatim as StartedUnixMs.
	startedAt := time.Now()

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
	// The set of identities we accept is the same either way: which end opens
	// the connection does not change who we are willing to talk to. Only the
	// shape of the TLS configuration differs.
	var tlsConf *tls.Config
	if dial != "" {
		tlsConf, err = identity.AgentDialTLS(key, authorized)
	} else {
		tlsConf, err = identity.AgentListenTLS(key, authorized)
	}
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	rtr, err := router.NewWithVhosts(routes, vhosts, router.AllowAll{})
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}

	// Our own pin, so a peer that turns out to be using our key is refused
	// rather than served as though it were a client.
	ownPin, err := identity.PinForKey(key)
	if err != nil {
		return fmt.Errorf("own pin: %w", err)
	}
	serveOpts := agentServeOpts(ag, idCfg, ownPin, startedAt)

	if ag.AllowRemoteRouteMutation {
		// Said out loud at the one moment an operator is certainly reading
		// this program's output. Every client this agent accepts can publish
		// names on it while it runs, and an operator who did not intend that
		// is the only person who can tell.
		slog.Warn("this agent accepts remote changes to what it publishes; "+
			"every authenticated client may publish names on it until it restarts",
			"role", "agent")
	}

	if dial != "" {
		return agentDialOut(ctx, dial, tlsConf, rtr, authorized, serveOpts)
	}

	// The agent binds a dual-stack ("udp") socket rather than an IPv4-only
	// ("udp4") socket. This is deliberate and correct for a passive listener:
	//
	// All client paths in this binary (connect/daemon/ping/stdio) bind "udp4"
	// because macOS dual-stack UDP sockets silently fail to *transmit* to
	// on-link IPv4 LAN peers — a hard-won lesson from early testing. That
	// rule applies to the initiating side, where the OS must route a fresh
	// outbound datagram with no prior context.
	//
	// The agent is the receiving side. It accepts whatever arrives on its
	// socket and responds *within the same socket context* — the remote
	// address comes from the arriving packet, so the OS has the routing
	// information it needs. The macOS restriction does not apply to this
	// response path. Binding "udp4" would break IPv6-only deployments and
	// prevent IPv6 clients from ever connecting.
	//
	// Do not change this to "udp4" without understanding the asymmetry above.
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
		"vhosts", rtr.Vhosts(),
		"authorized_clients", len(authorized),
	)
	return tunnel.Serve(ctx, ln, rtr, serveOpts)
}

// agentServeOpts turns the agent's settings into what the serving layer needs.
//
// It is a plain function of its inputs so that what an agent will actually do
// can be checked from a configuration file alone, without binding a socket or
// starting anything. Carrying a setting from a file to the code that acts on it
// is exactly the step that is easy to leave half-done, and this is where it
// becomes visible.
func agentServeOpts(ag config.Agent, idCfg config.Identity, ownPin string, startedAt time.Time) tunnel.ServeOpts {
	return tunnel.ServeOpts{
		WarnKeyAgeDays:           idCfg.WarnKeyAgeDays,
		OwnPin:                   ownPin,
		Version:                  buildinfo.Version(),
		StartedAt:                startedAt,
		AllowRemoteRouteMutation: ag.AllowRemoteRouteMutation,
	}
}

// agentDialOut runs the agent against a client that waits rather than connects.
// The route table and everything below it are unchanged; what is different is
// that this side opens the connection, and so is the side responsible for
// reopening it.
func agentDialOut(
	ctx context.Context,
	dial string,
	tlsConf *tls.Config,
	rtr *router.Router,
	authorized pinList,
	serveOpts tunnel.ServeOpts,
) error {
	// Refuse an address that could never be reached before opening a socket or
	// starting to retry. This end retries indefinitely by design, which is
	// right for a client that is merely switched off and wrong for an address
	// no amount of waiting can make work.
	if err := config.DialableAddr("client", dial); err != nil {
		return err
	}

	// Bind IPv4-only for the same reason every other initiating path in this
	// binary does: a dual-stack socket on macOS silently fails to transmit to
	// on-link IPv4 neighbours, because the first outbound datagram has no
	// prior context for the OS to route from. The agent's listening socket is
	// dual-stack precisely because it is not initiating, so the convention
	// there is the opposite one and must not be copied here.
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

	slog.Info("quic-link agent connecting out",
		"dial", dial,
		"targets", rtr.Targets(),
		"vhosts", rtr.Vhosts(),
		"authorized_clients", len(authorized),
	)

	return tunnel.DialAndServe(ctx, t, dial, rtr, backoff.Default(), tunnel.WallClock{}, serveOpts)
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
