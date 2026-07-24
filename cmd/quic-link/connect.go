package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

const (
	// portProbeBlocks is how many ten-port blocks the auto ssh/docker probe
	// tries before giving up (base, base+10, base+20, ...).
	portProbeBlocks = 10
	// portProbeWindow is how many consecutive ports a single-service probe
	// tries before giving up.
	portProbeWindow = 10
)

func newConnectCmd(a *app) *cobra.Command {
	var (
		serverFlag  string
		local       string
		localDocker string
		sshTarget   string
		keyFile     string
		pin         string
	)

	cmd := &cobra.Command{
		Use:   "connect [SERVER]",
		Short: "Run the local client endpoint, tunnelling traffic to the agent",
		Long: `Run the local client endpoint. It connects to a quic-link agent over QUIC,
authenticates via mutual Ed25519 pin exchange, then listens on local TCP ports
and forwards connections through the tunnel to the named targets on the agent.

SERVER is the name of a server defined in the config file. If omitted and
exactly one enabled server exists in the config, that server is used
automatically. Flags override the resolved server's settings.`,
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
				serverName = "" // flag-only, no config name
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

			// --- overlay Changed flags onto the resolved server ---------

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

			// --- resolve local ports -----------------------------------
			// Explicit --local / --local-docker flags are used verbatim. Auto
			// ports derive from the server name; ssh and docker are probed
			// together as a coherent block (stepping by ten) so they never
			// resolve to the same port when the base is contended. Probing each
			// service independently could hand both the same port and collide
			// at bind time.
			sshSet := flags.Changed("local")
			dockerSet := flags.Changed("local-docker")
			sshPort, dockerPort := config.LocalPorts(serverName, srv.LocalPorts)

			var localSSH, localDocker2 string
			switch {
			case sshSet && dockerSet:
				localSSH = local
				localDocker2 = localDocker
			case !sshSet && !dockerSet:
				s, d, perr := bindFreePortPair("127.0.0.1", sshPort, dockerPort, portProbeBlocks)
				if perr != nil {
					return fmt.Errorf("no free local port block for ssh/docker near %d/%d: %w",
						sshPort, dockerPort, perr)
				}
				localSSH = fmt.Sprintf("127.0.0.1:%d", s)
				localDocker2 = fmt.Sprintf("127.0.0.1:%d", d)
			case sshSet:
				localSSH = local
				port, perr := bindFreePort("127.0.0.1", dockerPort, portProbeWindow)
				if perr != nil {
					return fmt.Errorf("no free local port for docker (tried %d:%d): %w",
						dockerPort, dockerPort+portProbeWindow-1, perr)
				}
				localDocker2 = fmt.Sprintf("127.0.0.1:%d", port)
			default: // only --local-docker set
				localDocker2 = localDocker
				port, perr := bindFreePort("127.0.0.1", sshPort, portProbeWindow)
				if perr != nil {
					return fmt.Errorf("no free local port for ssh (tried %d:%d): %w",
						sshPort, sshPort+portProbeWindow-1, perr)
				}
				localSSH = fmt.Sprintf("127.0.0.1:%d", port)
			}

			// --- validate the effective config -------------------------
			// Register the resolved server (with flag overrides applied) under
			// its name — or a synthetic key when it came only from flags — so
			// Validate checks exactly the server this run will use, taking the
			// same path config-named servers take.
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

			return connectRun(cmd.Context(), srv.Addr, localSSH, localDocker2, sshTarget, effectiveKey, serverPin)
		},
	}

	cmd.Flags().StringVar(&serverFlag, "server", "", "host:port of the quic-link agent (overrides config)")
	cmd.Flags().StringVar(&local, "local", "", "local TCP address for the ssh target (default: deterministic from server name)")
	cmd.Flags().StringVar(&localDocker, "local-docker", "", "local TCP address for the docker target (default: deterministic from server name)")
	cmd.Flags().StringVar(&sshTarget, "ssh-target", "ssh", "logical target for --local (advanced; for unknown-target checks)")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().StringVar(&pin, "pin", "", "expected agent pin (base64; from `quic-link keygen` on the agent)")

	return cmd
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

// bindFreePort tries to bind host:base on TCP, incrementing by 1 up to
// base+window-1. Returns the first port that binds successfully, or an error
// if all attempts fail. The listener is closed immediately; the port is not
// reserved (the probe-to-bind race is accepted for this dev-ergonomics use).
func bindFreePort(host string, base, window int) (int, error) {
	for i := range window {
		port := base + i
		addr := fmt.Sprintf("%s:%d", host, port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("all ports in [%d, %d) busy", base, base+window)
}

// bindFreePortPair finds a coherent (ssh, docker) port pair, both free at the
// same instant, by stepping both bases together in ten-port blocks. Holding
// both listeners simultaneously during the probe guarantees the two services
// never receive the same port. The listeners are closed immediately; the ports
// are not reserved (the probe-to-bind race is accepted for this use).
func bindFreePortPair(host string, sshBase, dockerBase, blocks int) (ssh, docker int, err error) {
	for i := range blocks {
		off := i * 10
		sp, dp := sshBase+off, dockerBase+off
		l1, e1 := net.Listen("tcp", fmt.Sprintf("%s:%d", host, sp))
		if e1 != nil {
			continue
		}
		l2, e2 := net.Listen("tcp", fmt.Sprintf("%s:%d", host, dp))
		if e2 != nil {
			_ = l1.Close()
			continue
		}
		_ = l1.Close()
		_ = l2.Close()
		return sp, dp, nil
	}
	return 0, 0, fmt.Errorf("all %d ssh/docker port blocks near %d/%d busy", blocks, sshBase, dockerBase)
}

// connectRun is the implementation of the connect verb.
func connectRun(ctx context.Context, server, local, localDocker, sshTarget, keyFile, serverPin string) error {
	tlsConf, err := clientTLSFromFlags(keyFile, serverPin)
	if err != nil {
		return err
	}

	// Read our own key creation time so the agent can log a rotation reminder
	// if the key is old. Absence of the .meta file is fine — send nothing.
	keyCreated := readKeyCreatedRFC3339(expandTilde(keyFile))

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
	return tunnel.Connect(ctx, t, server, forwards, tunnel.ConnectOpts{KeyCreated: keyCreated})
}
