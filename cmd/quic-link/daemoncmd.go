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
			return runDaemonOwner(cmd, a.cfg, serverName)
		},
	}

	cmd.Flags().StringVar(&serverName, "server", "",
		"manage only this server (name from config); default manages all enabled servers")

	return cmd
}

// bindServerSocket binds the UDP socket a server needs, which differs by
// direction.
//
// A server we connect out to gets an ephemeral local port, bound IPv4-only:
// a dual-stack socket on macOS silently fails to transmit to on-link IPv4
// neighbours because no address resolution happens for the mapped form. A
// server that connects to us gets the address the operator configured, bound
// dual-stack so it is reachable over either family, which is the same choice
// the agent's own listener makes for the same reason.
func bindServerSocket(srvName string, srv config.Server, waiting bool) (*net.UDPConn, error) {
	if !waiting {
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
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
func runDaemonOwner(cmd *cobra.Command, cfg *config.Config, scope string) error {
	// Validate scope against the config before doing any I/O.
	if scope != "" {
		srv, ok := cfg.Servers[scope]
		if !ok {
			return usageErrorf("server %q not found in config; available servers: %s",
				scope, serverNameList(cfg.Servers))
		}
		if srv.Enabled != nil && !*srv.Enabled {
			return usageErrorf("server %q is disabled; set enabled = true in the config to use it",
				scope)
		}
		// Narrow the config to only the requested server. The original cfg is
		// not mutated — we build a shallow copy with a single-entry Servers map.
		narrowed := *cfg
		narrowed.Servers = map[string]config.Server{scope: srv}
		cfg = &narrowed
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
	keyPath := expandTilde(cfg.Identity.KeyFile)
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
	serverNames := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		serverNames = append(serverNames, name)
	}
	sort.Strings(serverNames)

	alloc := edge.PortAllocator{}
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

	return daemon.Run(cmd.Context(), cfg, sock, pool, daemon.WallClock{}, prebuiltListeners)
}
