package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/edge"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/names"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// singleInstanceProbeTimeout bounds how long the single-instance probe waits
// for a response from an already-running owner. If the probe times out we
// treat the socket as a squatter (outcome 3 — refuse, exit 2), not as absent.
const singleInstanceProbeTimeout = 2 * time.Second

// errOwnerRunningType is returned when a conforming owner is already answering
// the socket. It maps to exit 3.
type errOwnerRunningType struct {
	sock string
}

func (e *errOwnerRunningType) Error() string {
	return fmt.Sprintf("daemon owner already running (socket: %s); "+
		"use 'quic-link status' to check the fleet, or stop the running owner first",
		e.sock)
}

// errSquatterType is returned when something is connected to the socket but
// its response is not a conforming quic-link status reply (garbage bytes,
// unexpected schema, or a probe timeout that is not a clean ECONNREFUSED).
// A squatter gets exit 2 (usage/environment error) rather than exit 3 so the
// operator knows to investigate the socket path rather than simply waiting.
type errSquatterType struct {
	sock   string
	reason string
}

func (e *errSquatterType) Error() string {
	return fmt.Sprintf("socket %s is occupied by an unrecognized process (%s); "+
		"will not reclaim — investigate or remove it manually",
		e.sock, e.reason)
}

// probeSocket implements the three-outcome single-instance check:
//
//  1. Conforming response from a live owner → ErrOwnerRunning (→ exit 3).
//  2. Clean ECONNREFUSED / ENOENT (no listener, stale file) → canReclaim=true.
//  3. Socket responds but with garbage / non-conforming data → ErrSquatter (→ exit 2).
//
// The probe is self-bounding: ipc.Client.Probe sets singleInstanceProbeTimeout
// as a connection deadline, so this function always returns within that bound
// with no background goroutine left behind.
func probeSocket(sock string) (canReclaim bool, err error) {
	c := ipc.NewClient(sock)
	probeErr := c.Probe(singleInstanceProbeTimeout)

	if probeErr == nil {
		// A conforming owner answered — live owner, outcome 1.
		return false, &errOwnerRunningType{sock: sock}
	}
	if errors.Is(probeErr, ipc.ErrSchemaMismatch) {
		// An owner is running but with a different socket schema. Still a
		// live owner from our perspective — do not reclaim.
		return false, &errOwnerRunningType{sock: sock}
	}
	if errors.Is(probeErr, ipc.ErrDaemonAbsent) {
		// ECONNREFUSED (no listener) or ENOENT (socket file absent):
		// the socket is stale. Reclaim allowed.
		return true, nil
	}
	// Any other error (deadline exceeded, garbled bytes, unexpected close) is
	// treated as an occupied socket that we should not reclaim.
	return false, &errSquatterType{
		sock:   sock,
		reason: fmt.Sprintf("probe failed with unexpected error: %v", probeErr),
	}
}

// newDaemonCmd builds the daemon subcommand, which is the sole session owner.
// It runs in the foreground; the operator's service manager (systemd user unit,
// launchd agent, shell &) is responsible for backgrounding it.
func newDaemonCmd(a *app) *cobra.Command {
	var serverName string
	addServers := serverSpecList{flag: "server-add"}
	serverPins := serverSpecList{flag: "server-pin"}

	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the session owner in the foreground (manages QUIC sessions and the local socket)",
		Long: `Run the quic-link session owner in the foreground.

daemon is THE owner: it manages QUIC sessions to agent(s), binds the local TCP
edge ports, and serves the unix socket used by status, stdio, and fwd.

  No flag: manage all enabled servers in the config.
  --server NAME: manage only the named server (scoped pool — status reports
                 only that server).

Backgrounding is the operator's job: use a systemd user unit, launchd agent,
or a shell '&'. quic-link does not daemonise itself.

Exactly one owner may hold the socket at a time. A second invocation exits 3
and tells you to use 'quic-link status' or stop the running owner first.

Ctrl-C (SIGINT) or SIGTERM causes a bounded graceful drain then exit.`,
		Args: wrapArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := applyServerFlags(a.cfg, &addServers, &serverPins, a.configPath); err != nil {
				return err
			}
			return runDaemonOwner(cmd, a.cfg, serverName, a.configPath)
		},
	}

	cmd.Flags().StringVar(&serverName, "server", "",
		"manage only this server (name from config); default manages all enabled servers")
	cmd.Flags().Var(&addServers, "server-add",
		"define a server as NAME=ADDR, repeatable; replaces the servers in your settings file")
	cmd.Flags().Var(&serverPins, "server-pin",
		"the pin for a server defined with --server-add, as NAME=PIN, repeatable")

	return cmd
}

// bindServerSocket binds the UDP socket a server needs, which differs by
// direction.
//
// A server we connect out to gets an ephemeral local port in the family its
// address needs, one family per socket. A server that connects to us gets the
// address the operator configured, bound for both families so it is reachable
// either way, which is the same choice the agent's own listener makes for the
// same reason.
func bindServerSocket(srvName string, srv config.Server, waiting bool) (*net.UDPConn, error) {
	if !waiting {
		udpConn, err := bindDialingSocket(srv.Addr)
		if err != nil {
			return nil, fmt.Errorf("UDP socket for server %q: %w", srvName, err)
		}
		return udpConn, nil
	}

	addr, err := net.ResolveUDPAddr("udp", srv.Listen)
	if err != nil {
		return nil, usageErrorf("server %q: cannot understand listen address %q: %v",
			srvName, srv.Listen, err)
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, classifyListenBindError(srvName, srv.Listen, err)
	}
	return udpConn, nil
}

// classifyListenBindError turns a failed bind into a message an operator can
// act on. The classification is by error value, never by matching the text of
// the message, which varies by platform.
//
// A permission failure deliberately never suggests running as root. Doing so
// would put the long-lived identity key inside a privileged process to solve a
// problem that choosing a different port also solves.
func classifyListenBindError(srvName, listen string, err error) error {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return usageErrorf("server %q: listen address %s is already in use; "+
			"choose a different port or stop whatever is using it", srvName, listen)
	case errors.Is(err, syscall.EACCES):
		return usageErrorf("server %q: binding %s needs privileges this process does not have; "+
			"choose a port of 1024 or above instead", srvName, listen)
	default:
		return fmt.Errorf("server %q: bind listen address %s: %w", srvName, listen, err)
	}
}

// runDaemonOwner is the shared implementation used by both the daemon command
// and the connect command (which is a deprecated alias). scope is the server
// name from --server NAME; an empty string means "all enabled servers".
//
// When scope is non-empty the config is narrowed to contain only that server
// before the pool and edges are built, so status --json reports only the
// scoped server rather than the full fleet.
func runDaemonOwner(cmd *cobra.Command, cfg *config.Config, scope, configPath string) error {
	// Disable core dumps as the very first thing this function does, before
	// any config narrowing, socket probing, or key loading below. daemon.Run
	// also calls this (see internal/daemon/daemon.go), but by the time this
	// function reaches that call the identity key has already been loaded a
	// few lines down and the session pool has already dialed out - both of
	// which put private-key-bearing state into this process's memory well
	// before Run's own call would take effect. Calling it here closes that
	// gap; Run's call stays in place as a second call for the benefit of any
	// other caller of daemon.Run (tests do call it directly), and a second
	// call is harmless - the resource limit is already at zero when this
	// one runs.
	if err := daemon.DisableCoreDump(); err != nil {
		slog.Warn("daemon: could not disable core dumps", "role", "daemon", "err", err)
	}

	// Validate scope against the config before doing any I/O.
	if scope != "" {
		srv, ok := cfg.Servers[scope]
		if !ok {
			return usageErrorf("server %q not found in config; available servers: %s",
				scope, serverNameList(cfg.Servers))
		}
		if srv.Enabled != nil && !*srv.Enabled {
			// The name resolved, so this is not a mistake in the command: the
			// server is switched off, and the fix is to switch it on. That is a
			// state of the world rather than a usage error, which is how the
			// three verbs that reach a session already report it, and this verb
			// now agrees with them. A name absent from settings stays a usage
			// error above, because that is a typo or a missing block.
			fmt.Fprintf(cmd.ErrOrStderr(),
				"server %q is disabled; set enabled = true in the config to use it\n", scope)
			return &errFinalExitCode{
				code: 3,
				msg:  fmt.Sprintf("server %q is disabled", scope),
			}
		}
		// Narrow the config to only the requested server. The original cfg is
		// not mutated — we build a shallow copy with a single-entry Servers map.
		narrowed := *cfg
		narrowed.Servers = map[string]config.Server{scope: srv}
		cfg = &narrowed
	}

	// An owner with nothing to manage used to start anyway: the naming sockets
	// came up, the local API answered, and not one tunnel existed. From outside
	// that is indistinguishable from a misconfiguration, and the log said only
	// that it was serving names for no servers. Say what is missing instead.
	if len(cfg.Servers) == 0 {
		return usageErrorf("%s", describeMinimumViableRun(configPath))
	}

	// Resolve the socket path (also creates and verifies the directory).
	sock, err := daemonSocketPath(cfg)
	if err != nil {
		return err
	}

	// Three-outcome single-instance check.
	canReclaim, probeErr := probeSocket(sock)
	if probeErr != nil {
		// Either a live owner (→ exit 3) or a squatter (→ exit 2).
		return probeErr
	}
	if canReclaim {
		// Stale socket — remove it only after re-verifying the path is
		// safe (still inside the owned dir, not a symlink). The dir was
		// already verified by socketPath above; re-verify the socket
		// file itself is not a symlink before removing.
		if lst, err := os.Lstat(sock); err == nil {
			if lst.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("stale socket path %s is a symlink; will not remove: %w",
					sock, errUsage)
			}
		}
		if err := os.Remove(sock); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale socket %s: %w", sock, err)
		}
		slog.Info("stale socket reclaimed", "role", "daemon", "socket", sock)
	}

	// Validate the config for the daemon role.
	warnings, err := cfg.Validate(config.RoleClient)
	for _, w := range warnings {
		slog.Warn(w)
	}
	if err != nil {
		return err
	}

	// Load the identity key.
	keyPath := identity.ExpandHome(cfg.Identity.KeyFile)
	key, err := identity.LoadKey(keyPath)
	if err != nil {
		return fmt.Errorf("daemon: load identity key: %w", err)
	}

	// Key-age hygiene check.
	created, present, _ := identity.ReadMeta(keyPath)
	if present && cfg.Identity.WarnKeyAgeDays > 0 {
		ageDays := int(daemon.WallClock{}.Since(created).Hours() / 24)
		if ageDays > cfg.Identity.WarnKeyAgeDays {
			if cfg.Identity.RefuseOldKey {
				return usageErrorf("identity key is %d days old (threshold: %d); "+
					"rotate with 'quic-link keygen --force'",
					ageDays, cfg.Identity.WarnKeyAgeDays)
			}
			slog.Warn("identity key exceeds rotation age threshold",
				"role", "daemon",
				"key_age_days", ageDays,
				"warn_key_age_days", cfg.Identity.WarnKeyAgeDays,
			)
		}
	}

	// Build the transport factory: one QUIC transport per enabled server.
	makeTransport := func(srvName string, srv config.Server) (transport.Transport, error) {
		pin, err := identity.ParsePin(srv.Pin)
		if err != nil {
			return nil, fmt.Errorf("invalid pin for server %q: %w", srvName, err)
		}

		// Both shapes verify the same single expected server pin, because our
		// logical role does not change with the direction. What changes is that
		// a socket which accepts connections must require a certificate from
		// the peer, and one that opens them must not.
		waiting := srv.Listen != "" && srv.Addr == ""

		var tlsConf *tls.Config
		if waiting {
			tlsConf, err = identity.ClientListenTLS(key, pin)
		} else {
			tlsConf, err = identity.ClientDialTLS(key, pin)
		}
		if err != nil {
			return nil, fmt.Errorf("TLS config for server %q: %w", srvName, err)
		}

		udpConn, err := bindServerSocket(srvName, srv, waiting)
		if err != nil {
			return nil, err
		}
		var t transport.Transport
		if waiting {
			t, err = transport.NewQUICListenTransport(udpConn, tlsConf, nil)
		} else {
			t, err = transport.NewQUICTransport(udpConn, tlsConf, nil)
		}
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("transport for server %q: %w", srvName, err)
		}
		return t, nil
	}

	// Acquire the TCP listener pairs for all enabled servers before building
	// the pool. This is the single allocation point: both the pool (for status
	// reporting) and the edges (for accepting connections) consume the same
	// result, so the reported ports always reflect what is actually bound.
	//
	// Iteration is in sorted name order so that when two servers' deterministic
	// port blocks collide, the same server wins the base block on every restart.
	// Randomised map iteration would make the winner a coin flip.
	boundPorts, prebuiltListeners := acquireEdgeListeners(cfg, edge.PortAllocator{})

	// Take the naming sockets. Kept apart from the edge listeners on purpose:
	// an edge that cannot be bound costs one server its convenience ports,
	// while a naming socket that cannot be bound costs the whole machine its
	// names. Those are different failures and deserve different words.
	naming, namingErr := acquireNamingListeners(cfg)
	if namingErr != nil {
		// A name that cannot be served is the operator's to correct, so it stops
		// the daemon instead of degrading it. Every other naming failure is a
		// busy or forbidden socket, which costs this machine its names and
		// nothing else: those carry on, because the tunnels and the local ports
		// still work and saying so is more useful than refusing to run.
		if errors.Is(namingErr, names.ErrUnservableName) {
			return usageErrorf("%v", namingErr)
		}
		slog.Error("daemon: names are unavailable this session",
			"role", "daemon", "err", namingErr)
	}

	pool, err := daemon.NewRealPool(
		cmd.Context(),
		cfg,
		makeTransport,
		daemon.DefaultReconnectPolicy(),
		daemon.WallClock{},
		boundPorts,
	)
	if err != nil {
		// Close pre-acquired listeners to avoid a file-descriptor leak.
		for _, pair := range prebuiltListeners {
			pair[0].Close()
			pair[1].Close()
		}
		return fmt.Errorf("daemon: build pool: %w", err)
	}

	return daemon.Run(cmd.Context(), cfg, sock, pool, daemon.WallClock{}, prebuiltListeners, naming)
}

// pairAllocator acquires the (ssh, docker) listener pair for one server.
// edge.PortAllocator is the only implementation in the program; the interface
// exists so a test can make one server's acquisition fail on demand, which the
// real allocator only does when a hundred consecutive ports are already taken.
type pairAllocator interface {
	AcquirePair(server string, overrides map[string]int) (sshLn, dockerLn net.Listener, err error)
}

// acquireEdgeListeners binds the local listener pair for every enabled server
// and reports both the bound port numbers and the listeners themselves.
//
// This is the single allocation point: the session pool consumes the ports for
// status reporting and the edges consume the listeners for accepting, so what
// is reported always reflects what is actually bound.
//
// Servers are visited in sorted name order so that when two deterministic port
// blocks collide, the same server wins the base block on every restart.
// Randomised map iteration would make the winner a coin flip.
//
// A server whose pair cannot be acquired is logged and skipped. It is never
// fatal: one server whose port block is fully occupied must not stop the daemon
// from starting or take the other servers down with it. Such a server still
// gets a session — it simply has no local ports, which status reports as zero.
func acquireEdgeListeners(cfg *config.Config, alloc pairAllocator) (map[string][2]int, map[string][2]net.Listener) {
	serverNames := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		serverNames = append(serverNames, name)
	}
	sort.Strings(serverNames)

	boundPorts := make(map[string][2]int)
	prebuiltListeners := make(map[string][2]net.Listener)
	for _, name := range serverNames {
		srv := cfg.Servers[name]
		if srv.Enabled != nil && !*srv.Enabled {
			continue
		}
		sshLn, dkrLn, acquireErr := alloc.AcquirePair(name, srv.LocalPorts)
		if acquireErr != nil {
			slog.Error("daemon: cannot acquire port pair for server; skipping edge",
				"role", "daemon", "server", name, "err", acquireErr)
			continue
		}
		sshPort := sshLn.Addr().(*net.TCPAddr).Port
		dkrPort := dkrLn.Addr().(*net.TCPAddr).Port
		boundPorts[name] = [2]int{sshPort, dkrPort}
		prebuiltListeners[name] = [2]net.Listener{sshLn, dkrLn}
	}
	return boundPorts, prebuiltListeners
}

// acquireNamingListeners takes the sockets the naming layer answers on.
//
// Failure is never fatal: the rest of the product works without names, so a
// port already in use costs this session its name resolution and nothing else.
// It is reported plainly and named, because the alternative — quietly moving to
// another port — would leave the system resolver pointing at a port with
// nothing behind it, resolving nothing and explaining nothing.
//
// Both transports are taken together or not at all. Serving one without the
// other is a half-state nobody would predict, and there is no benefit to it:
// every answer this responder gives fits in a datagram.
func acquireNamingListeners(cfg *config.Config) (daemon.NamingListeners, error) {
	n, err := cfg.Naming()
	if err != nil {
		// Validation already refused this before we got here; treat it as
		// "no names" rather than assuming it cannot happen.
		return daemon.NamingListeners{}, err
	}

	servers := make([]string, 0, len(cfg.Servers))
	for name, srv := range cfg.Servers {
		if srv.Enabled != nil && !*srv.Enabled {
			// A disabled server has no session and no ports. Answering for its
			// name would produce something that resolves and then cannot be
			// reached, which is worse than not resolving at all.
			continue
		}
		servers = append(servers, name)
	}

	// Build the zone before taking any socket. A name this machine could answer
	// for but never serve stops the daemon here, while there is still nothing
	// to unwind and nothing has been published to the rest of the system.
	zone, err := names.NewZone(n.Suffix, servers)
	if err != nil {
		return daemon.NamingListeners{}, err
	}

	addr := fmt.Sprintf("127.0.0.1:%d", n.DNSPort)
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return daemon.NamingListeners{}, namingBindError(n.DNSPort, "udp", err)
	}
	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		udp.Close()
		return daemon.NamingListeners{}, namingBindError(n.DNSPort, "tcp", err)
	}

	httpLn, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", n.HTTPPort))
	if err != nil {
		udp.Close()
		tcp.Close()
		return daemon.NamingListeners{}, namingBindError(n.HTTPPort, "tcp", err)
	}

	httpsLn, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", n.HTTPSPort))
	if err != nil {
		udp.Close()
		tcp.Close()
		httpLn.Close()
		return daemon.NamingListeners{}, namingBindError(n.HTTPSPort, "tcp", err)
	}

	return daemon.NamingListeners{
		Zone:   zone,
		DNSUDP: udp,
		DNSTCP: tcp,
		HTTP:   httpLn,
		HTTPS:  httpsLn,
	}, nil
}

// namingBindError explains a failed naming bind in terms of what the user can
// do about it, and distinguishes the common case from everything else.
func namingBindError(port int, proto string, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf(
			"%s port %d is already held by another program, so names cannot be answered; "+
				"free that port, or set names.dns_port to a different one and register it again: %w",
			proto, port, err)
	}
	return fmt.Errorf("cannot listen for name queries on %s port %d: %w", proto, port, err)
}
