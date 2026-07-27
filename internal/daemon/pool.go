package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// ExponentialReconnectPolicy is the production reconnect policy: exponential
// backoff starting at Base, multiplied by Factor each attempt, capped at Cap.
// After StableAfter_ of connected uptime the attempt counter resets.
type ExponentialReconnectPolicy struct {
	Base         time.Duration
	Factor       float64
	Cap          time.Duration
	StableAfter_ time.Duration
}

// Backoff returns the wait duration before attempt n (0-indexed).
func (p ExponentialReconnectPolicy) Backoff(n int) time.Duration {
	d := float64(p.Base) * math.Pow(p.Factor, float64(n))
	if d > float64(p.Cap) {
		d = float64(p.Cap)
	}
	return time.Duration(d)
}

// StableAfter returns the uptime after which the backoff counter resets on drop.
func (p ExponentialReconnectPolicy) StableAfter() time.Duration {
	return p.StableAfter_
}

// DefaultReconnectPolicy returns the project-standard reconnect schedule:
// 250ms base, ×2 factor, 15s cap, reset after 60s of stable uptime.
func DefaultReconnectPolicy() ReconnectPolicy {
	return ExponentialReconnectPolicy{
		Base:         250 * time.Millisecond,
		Factor:       2,
		Cap:          15 * time.Second,
		StableAfter_: 60 * time.Second,
	}
}

// WallClock is the production Clock implementation using real wall-clock time.
type WallClock struct{}

// Now returns the current wall-clock time.
func (WallClock) Now() time.Time { return time.Now() }

// Since returns the duration elapsed since t.
func (WallClock) Since(t time.Time) time.Duration { return time.Since(t) }

// After returns a channel that fires after d.
func (WallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// ---- realPool ---------------------------------------------------------------

// realPool is the production SessionPool. It holds one SessionEntry per
// configured server.
type realPool struct {
	entries map[string]SessionEntry
	order   []string // stable iteration order for State()
}

// NewRealPool constructs a pool from the config. One dialEntry is created per
// enabled server; disabled servers get a disabledEntry stub. Dialing begins
// immediately (eager) for each enabled server.
//
// makeTransport is a factory called once per enabled server. It receives the
// server name and config and returns the transport to use for dialing.
func NewRealPool(
	ctx context.Context,
	cfg *config.Config,
	makeTransport func(serverName string, srv config.Server) (transport.Transport, error),
	policy ReconnectPolicy,
	clock Clock,
) (*realPool, error) {
	p := &realPool{
		entries: make(map[string]SessionEntry),
	}

	names := sortedServerNames(cfg.Servers)
	for _, name := range names {
		srv := cfg.Servers[name]
		sshPort, dockerPort := config.LocalPorts(name, srv.LocalPorts)

		if srv.Enabled != nil && !*srv.Enabled {
			p.entries[name] = &disabledEntry{
				name:       name,
				sshPort:    sshPort,
				dockerPort: dockerPort,
				since:      clock.Now(),
			}
			p.order = append(p.order, name)
			continue
		}

		t, err := makeTransport(name, srv)
		if err != nil {
			return nil, fmt.Errorf("pool: build transport for %q: %w", name, err)
		}

		entry := newDialEntry(ctx, name, srv.Addr, t, sshPort, dockerPort, policy, clock)
		p.entries[name] = entry
		p.order = append(p.order, name)
	}

	return p, nil
}

// Get returns the live transport connection for the named server.
func (p *realPool) Get(ctx context.Context, server string) (Conn, error) {
	entry, ok := p.entries[server]
	if !ok {
		return nil, fmt.Errorf("pool: unknown server %q", server)
	}
	return entry.Get(ctx)
}

// State returns a snapshot of all server connection states, in stable order.
func (p *realPool) State() []SessionState {
	states := make([]SessionState, 0, len(p.order))
	for _, name := range p.order {
		states = append(states, p.entries[name].State())
	}
	return states
}

// EntryState returns the connection-state string for a single server.
func (p *realPool) EntryState(server string) (string, error) {
	entry, ok := p.entries[server]
	if !ok {
		return "", fmt.Errorf("unknown server %q", server)
	}
	return entry.State().State, nil
}

// Close tears down all pool entries.
func (p *realPool) Close() {
	for _, entry := range p.entries {
		entry.Close(fmt.Errorf("daemon shutting down"))
	}
}

// sortedServerNames returns config server names in ascending order.
func sortedServerNames(servers map[string]config.Server) []string {
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

// ---- disabledEntry ----------------------------------------------------------

type disabledEntry struct {
	name       string
	sshPort    int
	dockerPort int
	since      time.Time
}

func (e *disabledEntry) Get(_ context.Context) (Conn, error) {
	return nil, fmt.Errorf("server %q is disabled", e.name)
}

func (e *disabledEntry) State() SessionState {
	return SessionState{
		Name:       e.name,
		State:      "disabled",
		Transport:  "dial",
		Since:      e.since,
		SSHPort:    e.sshPort,
		DockerPort: e.dockerPort,
	}
}

func (e *disabledEntry) Close(_ error) {}

// ---- dialEntry --------------------------------------------------------------

// internalConnState tracks the richer internal lifecycle. reconnecting and lost
// both project to "connecting" in the external enum (status --json). The
// distinction is log-text-only, not surfaced in the JSON.
type internalConnState int

const (
	stateConnecting internalConnState = iota
	stateConnected
	stateReconnecting
)

// dialEntry is the production SessionEntry for a forward-mode (dial-out)
// server. It establishes the connection eagerly at construction, opens the
// control stream, and re-dials continuously after every drop.
//
// Per-entry isolation is a hard invariant: no lock or goroutine is shared with
// other pool entries. One entry stuck in backoff cannot block another entry's
// State() snapshot or Get() call.
type dialEntry struct {
	name       string
	addr       string
	t          transport.Transport
	policy     ReconnectPolicy
	clock      Clock
	sshPort    int
	dockerPort int

	mu            sync.Mutex
	intState      internalConnState
	current       transport.Conn
	controlClient *control.Client
	// dialDone is closed when the in-flight dial finishes. It is non-nil only
	// while a dial is underway (dialing == true).
	dialDone chan struct{}
	dialing  bool
	dialErr  error
	since    time.Time

	cancel context.CancelFunc
	// runDone is closed when runLoop exits, allowing Close to detect completion.
	runDone chan struct{}
}

// newDialEntry creates a dialEntry and starts its run-loop immediately.
func newDialEntry(
	parentCtx context.Context,
	name, addr string,
	t transport.Transport,
	sshPort, dockerPort int,
	policy ReconnectPolicy,
	clock Clock,
) *dialEntry {
	ctx, cancel := context.WithCancel(parentCtx)
	e := &dialEntry{
		name:       name,
		addr:       addr,
		t:          t,
		policy:     policy,
		clock:      clock,
		sshPort:    sshPort,
		dockerPort: dockerPort,
		intState:   stateConnecting,
		since:      clock.Now(),
		dialing:    true,
		dialDone:   make(chan struct{}),
		cancel:     cancel,
		runDone:    make(chan struct{}),
	}
	go e.runLoop(ctx)
	return e
}

// runLoop is the per-entry goroutine. It dials, opens the control stream, waits
// for a drop, and repeats. It exits when ctx is cancelled.
func (e *dialEntry) runLoop(ctx context.Context) {
	defer close(e.runDone)

	attempt := 0
	var connectedAt time.Time

	for {
		if ctx.Err() != nil {
			// Wake any blocked Get callers with the ctx error.
			e.mu.Lock()
			e.dialErr = ctx.Err()
			done := e.dialDone
			e.dialing = false
			e.mu.Unlock()
			if done != nil {
				close(done)
			}
			return
		}

		conn, cclient, err := e.dialAndOpen(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Auth failures are permanent — no point retrying.
			if isAuthFailed(err) {
				slog.Error("session auth failed; giving up",
					"role", "daemon", "session", e.name, "err", err)
				e.mu.Lock()
				e.dialErr = err
				done := e.dialDone
				e.dialing = false
				e.mu.Unlock()
				if done != nil {
					close(done)
				}
				return
			}

			d := e.policy.Backoff(attempt)
			attempt++
			slog.Warn("session dial failed; will retry",
				"role", "daemon",
				"session", e.name,
				"attempt", attempt,
				"retry_in", d,
				"err", err,
			)

			// Record the error so Get() callers can surface it.
			e.mu.Lock()
			e.dialErr = err
			done := e.dialDone
			e.dialing = false
			e.mu.Unlock()
			if done != nil {
				close(done)
			}

			select {
			case <-ctx.Done():
				return
			case <-e.clock.After(d):
			}

			// Prepare for the next attempt.
			e.mu.Lock()
			e.dialing = true
			e.dialDone = make(chan struct{})
			e.dialErr = nil
			e.mu.Unlock()
			continue
		}

		// Successful dial — reset attempt counter.
		connectedAt = e.clock.Now()
		attempt = 0
		slog.Info("connected to server", "role", "daemon", "session", e.name)

		// Wait for the connection to drop.
		<-conn.Context().Done()

		if ctx.Err() != nil {
			return
		}

		// Reset attempt counter if we were stable long enough.
		if e.clock.Since(connectedAt) > e.policy.StableAfter() {
			attempt = 0
		}

		slog.Warn("session lost; reconnecting",
			"role", "daemon", "session", e.name)

		// Transition to reconnecting state and prepare the next dial slot.
		e.mu.Lock()
		e.intState = stateReconnecting
		e.current = nil
		e.since = e.clock.Now()
		if cclient != nil {
			_ = cclient.Close()
		}
		e.controlClient = nil
		e.dialing = true
		e.dialDone = make(chan struct{})
		e.dialErr = nil
		e.mu.Unlock()
	}
}

// dialAndOpen dials addr and opens the control stream. On success it records
// the live connection under the mutex and wakes blocked Get callers.
func (e *dialEntry) dialAndOpen(ctx context.Context) (transport.Conn, *control.Client, error) {
	conn, err := e.t.Dial(ctx, e.addr)
	if err != nil {
		return nil, nil, err
	}

	cclient, err := openControlStream(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(0x03, "control open failed")
		return nil, nil, err
	}

	// Record the live connection and wake blocked Get callers.
	e.mu.Lock()
	e.intState = stateConnected
	e.current = conn
	e.controlClient = cclient
	e.dialErr = nil
	done := e.dialDone
	e.dialing = false
	e.since = e.clock.Now()
	e.mu.Unlock()

	if done != nil {
		close(done)
	}

	return conn, cclient, nil
}

// Get returns the live transport connection, blocking if a dial is in progress.
func (e *dialEntry) Get(ctx context.Context) (Conn, error) {
	for {
		e.mu.Lock()
		if e.current != nil {
			c := e.current
			e.mu.Unlock()
			return c, nil
		}
		if !e.dialing {
			// No dial in progress and no current conn: auth failed or ctx cancelled.
			err := e.dialErr
			e.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("no connection available for %q", e.name)
		}
		done := e.dialDone
		e.mu.Unlock()

		select {
		case <-done:
			// Loop back to check e.current.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// State returns the current connection state snapshot.
func (e *dialEntry) State() SessionState {
	e.mu.Lock()
	defer e.mu.Unlock()

	stateStr := "connecting"
	if e.intState == stateConnected {
		stateStr = "connected"
	}

	return SessionState{
		Name:       e.name,
		State:      stateStr,
		Transport:  "dial",
		Since:      e.since,
		SSHPort:    e.sshPort,
		DockerPort: e.dockerPort,
	}
}

// Close cancels the entry's run-loop and closes the live connection.
func (e *dialEntry) Close(err error) {
	e.cancel()

	e.mu.Lock()
	conn := e.current
	cc := e.controlClient
	e.current = nil
	e.controlClient = nil
	e.mu.Unlock()

	if conn != nil {
		msg := "daemon shutting down"
		if err != nil {
			msg = err.Error()
		}
		_ = conn.CloseWithError(0, msg)
	}
	if cc != nil {
		_ = cc.Close()
	}

	// Wait for the run-loop to exit so we don't leak goroutines.
	<-e.runDone
}

// ---- helpers ----------------------------------------------------------------

// openControlStream opens the control gRPC stream on conn, classifying auth
// failures so the run-loop can stop retrying on a permanent rejection.
func openControlStream(ctx context.Context, conn transport.Conn) (*control.Client, error) {
	cclient, err := control.Open(ctx, conn, "quic-link daemon", control.OpenOpts{})
	if err != nil {
		if authErr := transport.AuthError(err); authErr != nil {
			return nil, authErr
		}
		if authErr := transport.AuthError(context.Cause(conn.Context())); authErr != nil {
			return nil, authErr
		}
		return nil, err
	}
	return cclient, nil
}

// isAuthFailed reports whether err is a transport authentication failure that
// will not self-heal (wrong pin, cert rejection).
func isAuthFailed(err error) bool {
	return transport.AuthError(err) != nil
}
