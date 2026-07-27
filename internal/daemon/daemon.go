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
//   - per-conn IPC handler: exits after the request/response pair (or at
//     the end of the attach splice in a later slice).
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
	"github.com/mauriciomem/quic-link/internal/ipc"
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

	// Stop accepting new connections. Existing in-flight handlers continue
	// until they finish or the drain deadline fires.
	srv.Close()

	// Wait for the IPC server drain with a bounded deadline. If the deadline
	// fires before all handlers finish, log a warning and proceed — never hang.
	drainTimer := time.NewTimer(shutdownDeadline)
	defer drainTimer.Stop()
	select {
	case <-ipcDone:
		// Clean drain completed.
	case <-drainTimer.C:
		slog.Warn("daemon: shutdown deadline exceeded; some handlers may still be running",
			"role", "daemon", "deadline", shutdownDeadline)
	}

	// Close all sessions after the IPC server has stopped so no new attaches
	// can race the pool teardown. CloseWithError propagates resets to any
	// active QUIC streams, which in turn unblock the (future) splice goroutines.
	pool.Close()

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
// and the daemon orchestrator. It mirrors transport.Conn but is defined here
// so internal/daemon does not import internal/transport directly.
type Conn interface {
	// Context returns the connection's lifecycle context; cancelled when
	// the connection closes.
	Context() context.Context
	// CloseWithError closes the connection with an application-level error.
	CloseWithError(code uint64, msg string) error
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

// poolAttachAdapter bridges SessionPool to ipc.AttachPool without importing
// internal/ipc from internal/daemon (the dependency points inward: daemon
// injects into ipc, not the other way around).
type poolAttachAdapter struct {
	pool SessionPool
}

func (a *poolAttachAdapter) EntryState(server string) (string, error) {
	return a.pool.EntryState(server)
}
