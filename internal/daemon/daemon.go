// Package daemon implements the lifecycle, session pool, and status snapshot
// for the quic-link daemon process. It orchestrates the session pool, the IPC
// socket server, and the signal-driven shutdown sequence. It does not implement
// any protocol or allocator directly — those live in internal/ipc, internal/tunnel,
// and internal/config respectively.
//
// # Goroutine ownership
//
// The daemon owns these goroutine families:
//
//   - dialEntry.runLoop (one per enabled server): dials eagerly at pool
//     construction and re-dials after every drop. Exits when the entry's
//     context is cancelled (pool.Close or root ctx).
//
//   - ipc.Server accept loop: exits when Server.Close is called.
//
//   - per-conn IPC handler: exits after the request/response pair (RPC)
//     or when the splice ends (attach). The splice goroutine is owned by
//     tunnel.Pipe and exits when both io.Copy directions complete.
//
//   - edge accept loops (two per enabled server: ssh and docker): exit when
//     their listener is closed (by Close() or the ctx-cancel goroutine in
//     the edge).
//
//   - per-accept-edge splice goroutines: spawned by the edge accept loop;
//     each runs tunnel.DoAttach in its own goroutine and exits when the
//     splice completes. Tracked by the edge's WaitGroup so edge.Close joins
//     them all.
//
//   - root ctx cancel goroutine: cancels the root context on the first
//     received signal; exits immediately.
//
// No goroutine is fire-and-forget. Every goroutine above has a clear exit path
// rooted in a cancelled context or a closed listener. goleak verifies this in
// the package's test suite.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/edge"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// shutdownDeadline is the maximum time Run waits for the IPC server to finish
// draining in-flight handlers after the root context is cancelled. If handlers
// are still running after this deadline, Run logs a warning and returns anyway
// rather than hanging forever. The socket file is always removed on both paths.
//
// Attach is a stub in this slice so the drain is instantaneous in practice;
// the deadline guards against a future splice that takes too long to unwind.
const shutdownDeadline = 5 * time.Second

// Run is the daemon's main entry point. It disables core dumps, starts the IPC
// server, and blocks until ctx is cancelled (SIGTERM/SIGINT). On return it
// drains the IPC server with a bounded deadline, closes all sessions, and
// removes the socket file. The socket is always removed, even if the drain
// deadline fires, so a future invocation can reclaim the path cleanly.
//
// Dependencies are passed as interfaces so tests can inject fakes without
// touching the QUIC or filesystem layers.
func Run(
	ctx context.Context,
	cfg *config.Config,
	socketPath string,
	pool SessionPool,
	clock Clock,
) error {
	// Disable core dumps at startup to remove the accidental-core-file
	// key-leak path. A core dump written while the key is resident in memory
	// could expose it. This does NOT defend against a same-uid debugger
	// (that is the accepted single-operator trust-boundary limitation).
	if err := disableCoreDump(); err != nil {
		// Non-fatal: log and continue. Not all environments support it.
		slog.Warn("daemon: could not disable core dumps", "role", "daemon", "err", err)
	}

	slog.Info("daemon starting", "role", "daemon", "socket", socketPath)

	// Build the status provider from the pool + config metadata.
	snap := &snapshotProvider{
		pool:  pool,
		cfg:   cfg,
		clock: clock,
	}

	// Build the IPC attach adapter (wraps the pool so ipc.Server doesn't
	// import internal/daemon).
	attachPool := &poolAttachAdapter{pool: pool}

	// Create and start the IPC server.
	srv := ipc.NewServer(socketPath, snap, attachPool)
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	// chmod the socket to 0600 immediately after binding. This is
	// umask-independent so the socket is never briefly world-readable.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		srv.Close()
		return fmt.Errorf("daemon: chmod socket: %w", err)
	}

	slog.Info("daemon started", "role", "daemon", "socket", socketPath)

	// Build one localPortEdge per enabled server. If a port pair cannot be
	// acquired for a server, log loudly and continue — one bad port must not
	// stop the entire fleet. The edge adapter satisfies both ipc.AttachPool and
	// edge.ConnSource via the same poolAttachAdapter struct.
	alloc := edge.PortAllocator{}
	var edges []*edge.LocalPortEdge
	for _, name := range sortedConfigServerNames(cfg.Servers) {
		srv := cfg.Servers[name]
		if srv.Enabled != nil && !*srv.Enabled {
			continue
		}
		sshLn, dkrLn, err := alloc.AcquirePair(name, srv.LocalPorts)
		if err != nil {
			slog.Error("daemon: cannot acquire port pair for server; skipping edge",
				"role", "daemon", "server", name, "err", err)
			continue
		}
		e := edge.NewLocalPortEdge(ctx, name, sshLn, dkrLn, attachPool)
		edges = append(edges, e)
		slog.Info("daemon: edge listening",
			"role", "daemon",
			"server", name,
			"ssh_port", sshLn.Addr(),
			"docker_port", dkrLn.Addr(),
		)
	}

	ipcDone := make(chan struct{})
	go func() {
		defer close(ipcDone)
		_ = srv.Serve(ctx)
	}()

	// Block until ctx is cancelled (signal or caller-driven teardown).
	<-ctx.Done()

	slog.Info("daemon shutting down", "role", "daemon")

	// Always remove the socket file so a future invocation can bind cleanly.
	// We defer this so it runs on both the normal-drain and deadline paths.
	defer func() {
		if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("daemon: remove socket", "role", "daemon", "err", err)
		}
		slog.Info("daemon exit", "role", "daemon")
	}()

	// Shutdown order matters: stop accepting new connections first, then reset
	// QUIC sessions (unblocking in-flight splices), then close the edges, then
	// wait for the IPC drain. Closing the pool before the IPC drain means every
	// in-flight splice's io.Copy will unblock quickly rather than waiting for
	// the idle timeout. Previously the pool was closed last, which caused every
	// SIGTERM to hang until the drain deadline fired.
	srv.Close()

	// Reset all pooled QUIC connections. This sends CONNECTION_CLOSE to the
	// agent and unblocks every active splice's io.Copy, allowing in-flight
	// IPC handlers to exit promptly.
	pool.Close()

	// Close all edge listeners (unblocks Accept) and join edge splice goroutines.
	for _, e := range edges {
		e.Close()
	}

	// Wait for the IPC server drain with a bounded deadline. The drain should
	// complete quickly now that the pool has been closed.
	drainTimer := time.NewTimer(shutdownDeadline)
	defer drainTimer.Stop()
	select {
	case <-ipcDone:
		// Clean drain completed.
	case <-drainTimer.C:
		slog.Warn("daemon: shutdown deadline exceeded; some handlers may still be running",
			"role", "daemon", "deadline", shutdownDeadline)
	}

	return ctx.Err()
}

// ---- DI interfaces ----------------------------------------------------------

// SessionPool manages the set of active server sessions. The daemon holds
// exactly one pool for its lifetime. Pool entries are created once at
// construction (eager) and reconnect automatically on drop. Each entry is
// isolated: one server stuck in backoff never blocks another's State() or Get.
type SessionPool interface {
	// Get returns a live transport connection for the named server, blocking
	// for an in-flight reconnect if one is underway. Returns an error if the
	// server is unknown, disabled, or the context is cancelled.
	Get(ctx context.Context, server string) (Conn, error)

	// State returns a snapshot of all server connection states, suitable for
	// serializing into the status response.
	State() []SessionState

	// EntryState returns the connection-state string for a single server.
	// Used by the IPC attach handler to validate server readiness without
	// importing the pool type directly.
	EntryState(server string) (string, error)

	// Close tears down all sessions and cancels in-flight dials.
	Close()
}

// Conn is the minimal surface of a transport connection needed by the pool
// and the daemon orchestrator. It mirrors the subset of transport.Conn that
// the IPC attach path and the pool lifecycle need. internal/daemon does import
// internal/transport (for the stream type in OpenStream and the type assertion
// in poolAttachAdapter.OpenConn); this interface keeps the DI surface narrow so
// test fakes only need to implement three methods.
type Conn interface {
	// Context returns the connection's lifecycle context; cancelled when
	// the connection closes.
	Context() context.Context
	// CloseWithError closes the connection with an application-level error.
	CloseWithError(code uint64, msg string) error
	// OpenStream opens a new outbound bidirectional stream to the peer.
	// This satisfies the tunnel.StreamConn interface so the attach splice path
	// can call DoAttach on a pooled Conn without importing internal/transport.
	OpenStream(ctx context.Context) (transport.Stream, error)
}

// SessionEntry is the per-server handle. A SessionPool holds one per enabled
// server. Both production constructions (dial-out and listen-for-agent) satisfy
// this interface, so the pool and the attach path are direction-blind.
// The listen-for-agent construction (reverse mode) is not yet implemented;
// this interface is designed so it will slot in without pool or status changes.
type SessionEntry interface {
	// Get returns the live transport connection, blocking for an in-flight
	// reconnect. The context bounds the wait.
	Get(ctx context.Context) (Conn, error)
	// State returns the current connection state for this entry.
	State() SessionState
	// Close tears down this entry: cancels the dial loop, closes the live
	// connection with CloseWithError, and unblocks any pending Get callers.
	Close(err error)
}

// ReconnectPolicy controls the backoff timing for a session that has dropped.
// Extracted behind an interface so tests can drive reconnect sequences without
// wall-clock waits.
type ReconnectPolicy interface {
	// Backoff returns the duration to wait before attempt number n (0-indexed).
	Backoff(n int) time.Duration
	// StableAfter returns the duration after which a connected session is
	// considered stable, resetting the backoff counter on the next drop.
	StableAfter() time.Duration
}

// Clock abstracts time so status snapshots and backoff timers are deterministic
// under test. Inject a fixed-time fake when building golden-file test data.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// Since returns the duration elapsed since t.
	Since(t time.Time) time.Duration
	// After returns a channel that fires after d.
	After(d time.Duration) <-chan time.Time
}

// SessionState is a point-in-time snapshot of one server session's state. It
// is produced by SessionEntry.State() and aggregated by SessionPool.State().
type SessionState struct {
	// Name is the server name from the config (e.g. "server1").
	Name string
	// State is the projected enum value for status --json. Exactly four values
	// are emitted in this release: "connected", "connecting", "listening",
	// "disabled". The enum is open: consumers must tolerate unrecognized values
	// by treating them as "not healthy / see logs".
	State string
	// Transport is "dial" for a dialEntry (the daemon dials the agent). It will
	// be "listen" for a reverse-mode listenEntry (not yet implemented).
	Transport string
	// Since is the time the entry entered its current state.
	Since time.Time
	// SSHPort and DockerPort are the computed local ports (from config.LocalPorts).
	// The daemon does not bind these ports in this slice; they are reported only.
	SSHPort    int
	DockerPort int
}

// ---- Status snapshot ---------------------------------------------------------

// StatusSnapshot is the JSON-serializable status document. It implements the
// frozen byte-shape of the status --json output. Do not add fields without
// bumping the schema field and regenerating the golden file. The golden test
// also guards against accidental leakage of key material — any future field
// carrying a full pin or private-key bytes would break the golden and force a
// deliberate review.
//
// The session enum is declared open: consumers must degrade on any unrecognized
// session string ("not healthy / see logs"). The four values emitted today
// are: "connected", "connecting", "listening", "disabled".
type StatusSnapshot struct {
	Schema   int              `json:"schema"`
	Identity *IdentityInfo    `json:"identity,omitempty"`
	Servers  []ServerSnapshot `json:"servers"`
}

// IdentityInfo carries local key age metadata. It is omitted entirely when
// the .meta sidecar is absent, preventing false rotation alarms.
type IdentityInfo struct {
	Created     string `json:"created"`
	AgeDays     int    `json:"age_days"`
	RotationDue bool   `json:"rotation_due"`
}

// ServerSnapshot is one entry in the servers array of the status snapshot.
type ServerSnapshot struct {
	Name       string      `json:"name"`
	Session    string      `json:"session"`
	Transport  string      `json:"transport"`
	SinceMS    int64       `json:"since_ms"`
	LocalPorts PortsInfo   `json:"local_ports"`
	Routes     []RouteInfo `json:"routes,omitempty"`
}

// PortsInfo carries the computed local port numbers for ssh and docker.
type PortsInfo struct {
	SSH    int `json:"ssh"`
	Docker int `json:"docker"`
}

// RouteInfo describes one agent route (populated only under --routes).
type RouteInfo struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	Builtin bool   `json:"builtin"`
}

// BuildSnapshot constructs a StatusSnapshot from the pool state, clock, and
// config metadata. It is a pure function: given the same inputs it always
// produces the same output, which makes it testable with a fixed clock and a
// fake pool without any I/O.
//
// keyPath is the path to the identity key file. The .meta sidecar is read from
// keyPath+".meta". If the sidecar is absent, the identity block is omitted.
// warnKeyAgeDays is the rotation-reminder threshold (0 disables the check).
func BuildSnapshot(
	states []SessionState,
	clock Clock,
	keyPath string,
	warnKeyAgeDays int,
	metaReader func(path string) (created time.Time, present bool, err error),
) StatusSnapshot {
	snap := StatusSnapshot{
		Schema:  1,
		Servers: make([]ServerSnapshot, 0, len(states)),
	}

	// Identity block — omit entirely when the sidecar is absent.
	created, present, err := metaReader(keyPath)
	if err == nil && present {
		ageDays := int(clock.Since(created).Hours() / 24)
		rotDue := warnKeyAgeDays > 0 && ageDays > warnKeyAgeDays
		snap.Identity = &IdentityInfo{
			Created:     created.UTC().Format(time.RFC3339),
			AgeDays:     ageDays,
			RotationDue: rotDue,
		}
	}

	for _, ss := range states {
		snap.Servers = append(snap.Servers, ServerSnapshot{
			Name:      ss.Name,
			Session:   ss.State,
			Transport: ss.Transport,
			SinceMS:   clock.Since(ss.Since).Milliseconds(),
			LocalPorts: PortsInfo{
				SSH:    ss.SSHPort,
				Docker: ss.DockerPort,
			},
			// Routes are populated only under --routes via the GetStatus relay
			// (omitted here; the agent does not yet implement GetStatus).
		})
	}

	return snap
}

// snapshotProvider implements ipc.StatusProvider by building a JSON snapshot
// from the pool + config on each call.
type snapshotProvider struct {
	pool       SessionPool
	cfg        *config.Config
	clock      Clock
	metaReader func(string) (time.Time, bool, error)
}

func (p *snapshotProvider) StatusJSON() ([]byte, error) {
	mr := p.metaReader
	if mr == nil {
		mr = readMetaFunc
	}
	states := p.pool.State()
	snap := BuildSnapshot(
		states,
		p.clock,
		p.cfg.Identity.KeyFile,
		p.cfg.Identity.WarnKeyAgeDays,
		mr,
	)
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal status snapshot: %w", err)
	}
	return b, nil
}

// NewStatusProvider returns an ipc.StatusProvider that builds compact JSON
// snapshots from pool, cfg, and clock on each call. metaReader overrides the
// default identity.ReadMeta; pass nil to use the default (reads the .meta
// sidecar from disk). Exported so tests can call StatusJSON() directly and
// verify that the golden bytes match the bytes the daemon emits over the socket.
func NewStatusProvider(
	pool SessionPool,
	cfg *config.Config,
	clock Clock,
	metaReader func(string) (time.Time, bool, error),
) interface{ StatusJSON() ([]byte, error) } {
	return &snapshotProvider{
		pool:       pool,
		cfg:        cfg,
		clock:      clock,
		metaReader: metaReader,
	}
}

// readMetaFunc is the default meta reader, pointing at identity.ReadMeta.
// It is a package-level variable so the snapshot builder can be tested
// without touching the filesystem.
var readMetaFunc = defaultReadMeta

// defaultReadMeta is the production implementation that reads the .meta sidecar.
func defaultReadMeta(keyPath string) (time.Time, bool, error) {
	return readIdentityMeta(keyPath)
}

// poolAttachAdapter bridges SessionPool to both ipc.AttachPool and
// edge.ConnSource without importing either package from internal/daemon (the
// dependency points inward). One struct, both interfaces.
type poolAttachAdapter struct {
	pool SessionPool
}

// EntryState satisfies the ipc.AttachPool interface.
func (a *poolAttachAdapter) EntryState(server string) (string, error) {
	return a.pool.EntryState(server)
}

// OpenConn satisfies both ipc.AttachPool and edge.ConnSource. It returns a live
// pooled connection for server, blocking for an in-flight reconnect up to the
// context deadline. The pool's Get is the readiness source of truth; the caller
// (both the IPC server and the edge accept loops) applies its own context
// deadline before calling this.
//
// The returned conn is a daemon.Conn which satisfies tunnel.StreamConn. The
// type assertion to transport.Conn is safe: the pool only ever stores real
// transport.Conn values (from QUIC) or mem.memConn values (from tests), both
// of which implement transport.Conn. If the assertion fails the peer certificates
// are unavailable and we return an empty pin prefix rather than failing.
func (a *poolAttachAdapter) OpenConn(ctx context.Context, server string) (tunnel.StreamConn, string, error) {
	c, err := a.pool.Get(ctx, server)
	if err != nil {
		return nil, "", fmt.Errorf("pool get %q: %w", server, err)
	}
	if c == nil {
		// A nil conn with no error means the pool has no connection for this
		// server yet (e.g. still connecting). Surface it as a not-ready error.
		return nil, "", fmt.Errorf("pool get %q: no connection available", server)
	}

	// Derive the peer pin prefix for the audit log. The pool stores transport.Conn
	// values; assert here — the single, documented, intentional type assertion in
	// the attach path.
	pinPrefix := ""
	if tc, ok := c.(transport.Conn); ok {
		if id, idErr := router.IdentityFromCerts(tc.PeerCertificates()); idErr == nil {
			pinPrefix = id.Short()
		}
	}
	if pinPrefix == "" {
		// The peer pin prefix is unavailable (e.g. certificates not yet
		// present on a freshly-dialed conn, or the type assertion failed for
		// a test fake). The attach proceeds anyway — the session is already
		// mutually authenticated; the prefix is for the audit log only.
		slog.Debug("attach: peer pin prefix unavailable for audit",
			"role", "daemon", "server", server)
	}

	return c, pinPrefix, nil
}

// sortedConfigServerNames returns config server names in ascending order.
// A thin wrapper over the config map so Run can iterate servers deterministically.
func sortedConfigServerNames(servers map[string]config.Server) []string {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}
