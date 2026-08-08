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
	"net"
	"os"
	"time"

	"github.com/mauriciomem/quic-link/internal/backoff"
	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/edge"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/names"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// shutdownDeadline is the maximum time Run waits for the IPC server to finish
// draining in-flight handlers after the root context is cancelled. If handlers
// are still running after this deadline, Run logs a warning and returns anyway
// rather than hanging forever. The socket file is always removed on both paths.
//
// A live attach splice can run for as long as its underlying session does, so
// this deadline is not expected to always be met while one is in flight; it
// exists so shutdown itself never hangs waiting for one to unwind.
const shutdownDeadline = 5 * time.Second

// DoctorSnapshot is what only the daemon can answer: which sockets it is
// actually holding, and whether a check reached its responder.
//
// It is deliberately a separate shape from the status snapshot. That one is a
// frozen contract other programs read; this one is a diagnosis aid that will
// grow, and growing a frozen thing is how a contract stops being one.
type DoctorSnapshot struct {
	Schema    int    `json:"schema"`
	Suffix    string `json:"suffix"`
	DNSPort   int    `json:"dns_port,omitempty"`
	HTTPPort  int    `json:"http_port,omitempty"`
	HTTPSPort int    `json:"https_port,omitempty"`
	// Servers this machine answers names for.
	Servers []string `json:"servers"`
	// ProbeSeen answers "did a check with this label reach the responder".
	ProbeSeen bool `json:"probe_seen"`
}

// NamingListeners carries the daemon-global sockets the naming layer answers
// on, already bound by the caller so that there is one place in the program
// where ports are taken.
//
// The two DNS fields are different types because the two transports are: a
// datagram socket is read from directly, while a stream socket is accepted on.
// Either may be nil, meaning that transport is not served — which is what
// happens when the port was already taken by something else.
type NamingListeners struct {
	Zone   *names.Zone
	DNSUDP net.PacketConn
	DNSTCP net.Listener
	HTTP   net.Listener
	HTTPS  net.Listener
}

// Run is the daemon's main entry point. It disables core dumps, starts the IPC
// server, and blocks until ctx is cancelled (SIGTERM/SIGINT). On return it
// drains the IPC server with a bounded deadline, closes all sessions, and
// removes the socket file. The socket is always removed, even if the drain
// deadline fires, so a future invocation can reclaim the path cleanly.
//
// prebuiltListeners carries the already-bound TCP listener pairs keyed by
// server name. Each entry is [ssh, docker]. Passing pre-built listeners rather
// than acquiring them inside Run ensures the pool and the edges consume the
// same result: there is exactly one place where ports are bound. A nil map
// means "no edges" (used in tests that do not need the local-port edge layer).
//
// naming carries the sockets the naming layer answers on. Unlike the edge
// listeners these belong to the daemon as a whole rather than to any one
// server, so they arrive separately. Its zero value means "no naming layer",
// which is what a test that does not care about names passes.
//
// Dependencies are passed as interfaces so tests can inject fakes without
// touching the QUIC or filesystem layers.
func Run(
	ctx context.Context,
	cfg *config.Config,
	socketPath string,
	pool SessionPool,
	clock Clock,
	prebuiltListeners map[string][2]net.Listener,
	naming NamingListeners,
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
	// The routes relay is wired unconditionally: it depends only on the
	// session pool, not on the naming layer (unlike doctor, just below).
	srv.SetRoutes(NewRoutesProvider(pool))
	if naming.Zone != nil {
		srv.SetDoctor(&doctorProvider{naming: naming})
	}
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

	// Build one localPortEdge per pre-acquired listener pair. The listeners were
	// bound before the pool was constructed so the pool and the edges share the
	// same result — there is exactly one place where ports are allocated.
	var edges []*edge.LocalPortEdge
	for _, name := range sortedConfigServerNames(cfg.Servers) {
		pair, ok := prebuiltListeners[name]
		if !ok {
			continue
		}
		sshLn, dkrLn := pair[0], pair[1]
		e := edge.NewLocalPortEdge(ctx, name, sshLn, dkrLn, attachPool)
		edges = append(edges, e)
		slog.Info("daemon: edge listening",
			"role", "daemon",
			"server", name,
			"ssh_port", sshLn.Addr(),
			"docker_port", dkrLn.Addr(),
		)
	}

	// Start answering for names. The responder reads a fixed set of names and
	// replies with a loopback address; it opens no session and holds no state
	// beyond that set, which is why it can be started here and stopped first.
	var resolver *names.Server
	if naming.DNSUDP != nil || naming.DNSTCP != nil {
		resolver = names.NewServer(ctx, naming.Zone, naming.DNSUDP, naming.DNSTCP)
		slog.Info("daemon: answering for names",
			"role", "daemon",
			"suffix", naming.Zone.Suffix(),
			"servers", len(naming.Zone.Servers()),
		)
	}

	// The name-routed edges. Unlike the per-server edges these are one listener
	// each for the whole machine: which server a connection belongs to is
	// decided from the name inside the request, not from the port it arrived on.
	var hostEdges []*edge.HostEdge
	if naming.HTTP != nil {
		hostEdges = append(hostEdges, edge.NewHostEdge(ctx, naming.HTTP, naming.Zone, attachPool, edge.HTTPPeeker{}))
		slog.Info("daemon: routing by name",
			"role", "daemon", "kind", "http", "addr", naming.HTTP.Addr())
	}
	if naming.HTTPS != nil {
		hostEdges = append(hostEdges, edge.NewHostEdge(ctx, naming.HTTPS, naming.Zone, attachPool, edge.SNIPeeker{}))
		slog.Info("daemon: routing by name",
			"role", "daemon", "kind", "https", "addr", naming.HTTPS.Addr())
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

	// Stop answering for names next. The responder is closed early, and
	// deliberately not alongside the edges: it answers from a fixed set of
	// names and never opens a session, so unlike an edge it has nothing
	// in flight that needs the pool to still be alive in order to finish.
	// It is stopped as soon as shutdown begins simply so it does not keep
	// handing out an address for a daemon that is going away.
	if resolver != nil {
		resolver.Close()
	}

	// Reset all pooled QUIC connections. This sends CONNECTION_CLOSE to the
	// agent and unblocks every active splice's io.Copy, allowing in-flight
	// IPC handlers to exit promptly.
	pool.Close()

	// Close all edge listeners (unblocks Accept) and join edge splice goroutines.
	// The name-routed edges belong here rather than with the responder: they do
	// open streams, so anything of theirs still in flight needs the pool to have
	// been closed first in order to unwind.
	for _, e := range hostEdges {
		e.Close()
	}
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

	// ControlCall relays fn to the named server's current control client, if
	// one is available right now. It is a straight lookup-then-delegate to
	// the entry's own ControlCall — see SessionEntry.ControlCall for the
	// full contract. Returns the same not-found error Get and EntryState
	// already use when server names nothing in the pool.
	ControlCall(ctx context.Context, server string, fn func(ctx context.Context, c *control.Client) error) error

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
// server.
//
// The interface is intentionally direction-agnostic. dialEntry (the daemon
// dials the agent), listenEntry (the agent dials the daemon), and
// disabledEntry (nothing dials anything) all satisfy it with the same
// method set, so nothing above this interface — SessionPool, the attach
// path, the status snapshot, or ControlCall's own callers — needs to know
// which kind of entry it is talking to. The distinction between the two
// live directions is carried by SessionState.Transport, which dialEntry
// reports as "dial" and listenEntry reports as "listen". No method here
// leaks a dial-only assumption: Get blocks for any in-flight negotiation
// regardless of direction, State snapshots the current state, Close tears
// down whatever mechanism the entry uses, and ControlCall relays an
// administrative call to whichever control client the entry currently
// holds, if any.
type SessionEntry interface {
	// Get returns the live transport connection, blocking for an in-flight
	// reconnect (or, for a listenEntry, for the incoming agent connection).
	// The context bounds the wait.
	Get(ctx context.Context) (Conn, error)
	// State returns the current connection state for this entry.
	State() SessionState
	// Close tears down this entry: cancels the run loop, closes the live
	// connection with CloseWithError, and unblocks any pending Get callers.
	Close(err error)

	// ControlCall copies the entry's current control client under a brief
	// lock, releases the lock, and only then invokes fn with the copy — fn
	// never runs while any entry-internal lock is held, and the raw client
	// pointer never crosses this boundary any other way. Both properties
	// matter for the same underlying reason: a reconnect can replace or
	// drop the control client at any moment. Holding a lock across fn's own
	// network call would let one slow or unreachable agent stall every
	// other operation that lock also guards on this entry — a new Get, a
	// State snapshot, the entry's own reconnect bookkeeping, and Close
	// during shutdown. Letting the raw client escape some other way would
	// let a caller race the exact moment a reconnect nils it out. Copying
	// under the lock and calling after releasing it avoids both at once.
	//
	// fn is called with a context bounded by DefaultControlCallTimeout (or
	// whatever is left of ctx's own deadline, if that is sooner); it must
	// use that context for its own call so a wedged agent cannot hang the
	// caller indefinitely.
	//
	// Returns an error describing why no call could be made when the entry
	// currently holds no control client at all — connecting, listening for
	// a peer, disabled, or permanently auth-failed — without calling fn.
	// Otherwise it returns whatever fn itself returns, including an error
	// from a call that started against a live client but lost it partway
	// through (a session dropping mid-call is treated the same way the
	// liveness probe already treats a captured client going stale mid-probe:
	// an ordinary failure, not a special case).
	ControlCall(ctx context.Context, fn func(ctx context.Context, c *control.Client) error) error
}

// ReconnectPolicy controls the backoff timing for a session that has dropped.
// It is an alias for the shared policy interface: whichever endpoint dials owns
// reconnection, which is this side in forward mode and the agent in reverse
// mode, so the schedule itself lives in a package both can import.
type ReconnectPolicy = backoff.Policy

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
	// State is the projected enum value for status --json. Five values are
	// emitted: "connected", "connecting", "listening", "disabled",
	// "auth_failed". The enum is open: consumers must tolerate unrecognized
	// values by treating them as "not healthy / see logs".
	State string
	// Transport is "dial" for a dialEntry (the daemon dials the agent). It will
	// be "listen" for a reverse-mode listenEntry (not yet implemented).
	Transport string
	// Since is the time the entry entered its current state.
	Since time.Time
	// SSHPort and DockerPort are the local TCP ports actually bound by the
	// daemon for this server (ssh and docker targets respectively). A disabled
	// server or a server whose port acquisition failed at startup reports 0
	// for both fields — zero means nothing is listening on that port.
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
// session string ("not healthy / see logs"). Five values are emitted:
// "connected", "connecting", "listening", "disabled", "auth_failed".
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

// RouteInfo describes one agent route, as reported live by the agent over
// the control-plane routes relay. It is shared, field-for-field, by both
// ServerSnapshot.Routes (declared here but never populated by BuildSnapshot —
// see the comment where that field would be filled in, below) and
// RoutesSnapshot (routes.go), the type the routes relay actually returns.
type RouteInfo struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	Builtin bool   `json:"builtin"`
	// Provenance says where the agent got this entry. It is omitted when
	// empty rather than published as a blank value, because an agent too
	// old to report it has said nothing on the subject, and "absent" is the
	// honest way to render that.
	Provenance string `json:"provenance,omitempty"`
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
			// Routes is deliberately left at its zero value here. Populating
			// it would mean this pure function makes a network call to the
			// agent, breaking its own contract (see the doc comment above)
			// and making plain "status --json" pay the latency and failure
			// modes of a live control-plane RPC for a field most callers
			// never look at. A live route table is available through its
			// own relay (RoutesSnapshot, routes.go), fetched only when asked.
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

// doctorProvider answers what only a running daemon can: the sockets it is
// actually holding, and whether a check reached its responder.
type doctorProvider struct{ naming NamingListeners }

func (d *doctorProvider) DoctorJSON(probe string) ([]byte, error) {
	snap := DoctorSnapshot{
		Schema:  1,
		Suffix:  d.naming.Zone.Suffix(),
		Servers: d.naming.Zone.Servers(),
	}
	// Only report a port that is actually bound. A number from configuration
	// would describe an intention; this describes what is true.
	if d.naming.DNSUDP != nil {
		if a, ok := d.naming.DNSUDP.LocalAddr().(*net.UDPAddr); ok {
			snap.DNSPort = a.Port
		}
	}
	if d.naming.HTTP != nil {
		if a, ok := d.naming.HTTP.Addr().(*net.TCPAddr); ok {
			snap.HTTPPort = a.Port
		}
	}
	if d.naming.HTTPS != nil {
		if a, ok := d.naming.HTTPS.Addr().(*net.TCPAddr); ok {
			snap.HTTPSPort = a.Port
		}
	}
	if probe != "" {
		snap.ProbeSeen = d.naming.Zone.SawProbe(probe)
	}
	return json.Marshal(snap)
}
