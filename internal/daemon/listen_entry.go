package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// Session close codes used when this side ends a connection deliberately. They
// match the codes the protocol reserves for these two situations.
const (
	// controlStreamMissingCode is sent when the control stream never became
	// usable on a connection that had otherwise been accepted.
	controlStreamMissingCode = 0x03
	// replacedSessionCode is sent to an incumbent connection that a newer
	// authenticated peer has displaced. It is the administrative-shutdown code:
	// from the incumbent's point of view this side is deliberately ending the
	// session, not failing.
	replacedSessionCode = 0x05
)

// listenAcceptRetryDelay is how long the accept loop pauses after a fault that
// is not a shutdown, such as running out of file descriptors. It is a fixed
// short pause rather than a backoff schedule: there is no attempt sequence to
// space out here, only a transient local fault to avoid spinning on.
const listenAcceptRetryDelay = 250 * time.Millisecond

// neverSeenPeerWarnAfter is how long a waiting server goes without any peer
// before it says so. Both ends being configured to wait is silent otherwise:
// nothing errors, nothing retries, and the status output looks like a healthy
// idle server forever.
const neverSeenPeerWarnAfter = 60 * time.Second

// controlOpenTimeout bounds how long we spend opening our control stream to a
// peer that has just connected. A peer that completes its handshake and then
// stalls must not hold up the accept loop, and must not displace a session that
// is currently working.
const controlOpenTimeout = 5 * time.Second

// listenEntry is the SessionEntry for a server this machine waits for rather
// than dials. The agent opens the transport; we accept it, and from there the
// roles are exactly as they are in the other direction: we are still the
// client, so we still open the control stream and the agent still serves it.
//
// It deliberately has no reconnect policy and no socket rebind. Both belong to
// dialing. Accept is a blocking wait, not a retry, so there is no attempt
// sequence to back off; and the rebind exists to escape a poisoned outbound
// path, which a socket that only ever receives does not have. Rebinding here
// would change the address the agent was told to connect to.
//
// Per-entry isolation holds as it does for a dialing entry: nothing here is
// shared with another entry, so a server that no peer ever connects to cannot
// stall a healthy one.
type listenEntry struct {
	name string
	ln   transport.Listener
	// t owns ln's underlying socket and is closed on shutdown to release it.
	t          transport.Transport
	clock      Clock
	liveness   LivenessPolicy
	sshPort    int
	dockerPort int
	// ownPin is this daemon's own identity, used to refuse a peer that turns
	// out to be using it. Empty disables the check.
	ownPin string

	mu            sync.Mutex
	intState      internalConnState
	current       transport.Conn
	controlClient *control.Client
	since         time.Time
	// everConnected separates "no peer has ever arrived", which may mean both
	// ends are waiting for each other, from "the peer left and we are waiting
	// again", which is ordinary.
	everConnected bool
	// waiting is closed when a connection becomes usable, so Get can block for
	// a peer the way it blocks for a dial in the other direction. It is
	// replaced on every drop.
	waiting chan struct{}
	// waitErr is set by failWaiters just before it closes waiting, so a Get
	// call that wakes from that close has something to read besides the
	// still-nil current connection. It is cleared by promote, mirroring how
	// dialEntry clears dialErr once a connection becomes usable — a stale
	// shutdown cause must not outlive the shutdown it described.
	waitErr error

	// watchers tracks the per-session goroutines so shutdown can join them.
	watchers sync.WaitGroup

	cancel  context.CancelFunc
	runDone chan struct{}
}

// newListenEntry creates a listenEntry and starts its accept loop.
func newListenEntry(
	parentCtx context.Context,
	name string,
	ln transport.Listener,
	t transport.Transport,
	sshPort, dockerPort int,
	ownPin string,
	clock Clock,
	liveness LivenessPolicy,
) *listenEntry {
	ctx, cancel := context.WithCancel(parentCtx)
	e := &listenEntry{
		name:       name,
		ln:         ln,
		t:          t,
		clock:      clock,
		liveness:   liveness,
		sshPort:    sshPort,
		dockerPort: dockerPort,
		ownPin:     ownPin,
		intState:   stateConnecting,
		since:      clock.Now(),
		waiting:    make(chan struct{}),
		cancel:     cancel,
		runDone:    make(chan struct{}),
	}
	go e.runLoop(ctx)
	return e
}

// runLoop accepts connections for the life of the entry. Unlike the dialing
// loop it never gives up and never backs off: it waits.
func (e *listenEntry) runLoop(ctx context.Context) {
	defer close(e.runDone)

	slog.Info("waiting for agent to connect",
		"role", "daemon", "session", e.name, "listen", e.ln.Addr().String())
	go e.warnIfNoPeerEverArrives(ctx)

	for {
		if ctx.Err() != nil {
			e.failWaiters(ctx.Err())
			return
		}

		conn, err := e.ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				e.failWaiters(ctx.Err())
				return
			}
			// A fault that is not our own shutdown: file-descriptor exhaustion
			// is the realistic one. Pause briefly so the loop does not spin,
			// then keep listening — the condition is usually transient and
			// giving up would strand the server permanently.
			slog.Error("accept failed; still listening",
				"role", "daemon", "session", e.name, "err", err)
			select {
			case <-ctx.Done():
				e.failWaiters(ctx.Err())
				return
			case <-e.clock.After(listenAcceptRetryDelay):
			}
			continue
		}

		if !e.promote(ctx, conn) {
			// The newcomer never became usable. Any existing session is
			// untouched; go back to accepting.
			continue
		}

		// Watch the new session in the background. Accepting has to continue
		// while a session is live, because an agent that reconnects after a
		// drop this side has not noticed yet arrives as a new connection while
		// the stale one still looks current. Blocking here until the old
		// session ended would leave that agent unable to get back in until the
		// liveness probe caught up.
		e.watchers.Add(1)
		go func() {
			defer e.watchers.Done()
			e.serveUntilDrop(ctx, conn)
		}()
	}
}

// promote decides whether a freshly accepted connection becomes this server's
// live session, and installs it if so.
//
// The gate is that OUR control stream to the peer opens successfully. We are
// the client here regardless of who opened the transport, so the control stream
// is something we open, not something we wait to observe. A peer that completes
// the handshake and then stalls fails this gate, which is what keeps it from
// displacing a session that is currently working.
func (e *listenEntry) promote(ctx context.Context, conn transport.Conn) bool {
	peer := peerPrefix(conn)

	// A peer holding any key other than the one we expect was already refused
	// during the handshake. The case that survives is the peer holding OUR key,
	// which means one identity is doing duty for both ends and neither of us
	// can tell which role the other is playing.
	if id, err := router.IdentityFromCerts(conn.PeerCertificates()); err == nil &&
		tunnel.SameIdentityAsPeer(e.ownPin, id) {
		slog.Error("incoming peer is using our own identity; refusing it. "+
			"Both ends are configured with the same key: generate a separate key for each end",
			"role", "daemon", "session", e.name, "peer", peer)
		_ = conn.CloseWithError(tunnel.RoleMismatchCode, "peer presented our own identity")
		return false
	}

	openCtx, cancel := context.WithTimeout(ctx, controlOpenTimeout)
	cclient, err := openControlStream(openCtx, conn)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			_ = conn.CloseWithError(0, "daemon shutting down")
			return false
		}
		slog.Warn("incoming connection did not become usable; keeping any existing session",
			"role", "daemon", "session", e.name, "peer", peer, "err", err)
		_ = conn.CloseWithError(controlStreamMissingCode, "control stream could not be opened")
		return false
	}

	e.mu.Lock()
	previous := e.current
	previousControl := e.controlClient
	e.current = conn
	e.controlClient = cclient
	e.intState = stateConnected
	e.since = e.clock.Now()
	firstEver := !e.everConnected
	e.everConnected = true
	e.waitErr = nil
	close(e.waiting)
	e.waiting = make(chan struct{})
	e.mu.Unlock()

	if previous != nil {
		// A newer authenticated peer displaces the incumbent. Say so loudly:
		// an operator who did not expect it is the only person who can tell
		// whether two machines are sharing one identity.
		slog.Warn("session replaced by a newer authenticated connection",
			"role", "daemon", "session", e.name, "peer", peer)
		if previousControl != nil {
			_ = previousControl.Close()
		}
		_ = previous.CloseWithError(replacedSessionCode, "replaced by a newer authenticated connection")
	}

	if firstEver {
		slog.Info("connected to server", "role", "daemon", "session", e.name, "peer", peer)
	} else {
		slog.Info("reconnected to server", "role", "daemon", "session", e.name, "peer", peer)
	}
	return true
}

// serveUntilDrop watches a live connection, running the same liveness probe the
// dialing side runs, and returns once the connection is gone.
func (e *listenEntry) serveUntilDrop(ctx context.Context, conn transport.Conn) {
	e.mu.Lock()
	cclient := e.controlClient
	isCurrent := e.current == conn
	e.mu.Unlock()
	if !isCurrent {
		// Already displaced by a newer connection before we got here.
		return
	}

	probeResult := make(chan *probeDeathDetail, 1)
	probeDone := make(chan struct{})
	probeCtx, probeCancel := context.WithCancel(ctx)
	go func() {
		defer close(probeDone)
		e.runLivenessProbe(probeCtx, conn, cclient, probeResult)
	}()

	<-conn.Context().Done()
	probeCancel()
	<-probeDone

	if ctx.Err() != nil {
		return
	}

	select {
	case detail := <-probeResult:
		slog.Warn("session lost; waiting for the agent to reconnect",
			"role", "daemon", "session", e.name,
			"detector", "liveness_probe",
			"consecutive_probe_failures", detail.consecutiveFailures,
		)
	default:
		slog.Warn("session lost; waiting for the agent to reconnect",
			"role", "daemon", "session", e.name,
			"detector", "quic_drop",
		)
	}

	// Only clear the slot if this connection is still the current one. A
	// replacement may have installed a newer connection while this one was
	// being torn down, and clearing then would drop a healthy session.
	//
	// The control client is released here and only here for a session that
	// ended on its own. One that was displaced instead had its control client
	// closed by whoever displaced it, so ownership never overlaps.
	e.mu.Lock()
	stillCurrent := e.current == conn
	if stillCurrent {
		e.intState = stateConnecting
		e.current = nil
		e.controlClient = nil
		e.since = e.clock.Now()
	}
	e.mu.Unlock()

	if stillCurrent && cclient != nil {
		_ = cclient.Close()
	}
}

// runLivenessProbe reuses the dialing entry's probe unchanged. The control
// client lives on this side of the connection in both directions, so the probe
// does not care who opened the transport.
func (e *listenEntry) runLivenessProbe(
	probeCtx context.Context,
	conn transport.Conn,
	cclient *control.Client,
	probeResult chan<- *probeDeathDetail,
) {
	runLivenessProbeOn(probeCtx, e.clock, e.liveness, e.name, conn, cclient, probeResult)
}

// warnIfNoPeerEverArrives says something when nothing ever connects. Both ends
// configured to wait produces no error on either machine and no retry traffic,
// so without this the only symptom is that nothing works. It fires once: a
// repeated warning on a timer would bury the logs it is meant to draw attention
// to. It is phrased as a possibility because a peer that is simply not running
// yet looks identical from here, and that is the most this side can know.
func (e *listenEntry) warnIfNoPeerEverArrives(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-e.clock.After(neverSeenPeerWarnAfter):
	}

	e.mu.Lock()
	seen := e.everConnected
	e.mu.Unlock()
	if seen {
		return
	}

	slog.Warn("no agent has connected since startup; "+
		"if the agent is also configured to wait for a connection, neither end will ever start one — "+
		"exactly one end must be the one that connects",
		"role", "daemon", "session", e.name,
		"waited", neverSeenPeerWarnAfter,
	)
}

// Get returns the live connection, blocking until a peer connects or ctx ends.
func (e *listenEntry) Get(ctx context.Context) (Conn, error) {
	for {
		e.mu.Lock()
		conn := e.current
		waitErr := e.waitErr
		wait := e.waiting
		e.mu.Unlock()

		if conn != nil {
			return conn, nil
		}
		if waitErr != nil {
			return nil, fmt.Errorf("server %q: no agent has connected yet: %w", e.name, waitErr)
		}

		select {
		case <-wait:
			// Either a peer arrived or failWaiters ran; loop and pick up
			// whichever one it was from e.current/e.waitErr above.
		case <-ctx.Done():
			return nil, fmt.Errorf("server %q: no agent has connected yet: %w", e.name, ctx.Err())
		}
	}
}

// listenStateLabel projects a listenEntry's internal state to the external
// enum value reported by both State() and the not-available message
// ControlCall produces when no client is currently held, so the two cannot
// silently drift apart. A server with no live peer reports "listening"
// whether or not it has ever had one; the difference between never having
// seen a peer and waiting for one to come back is carried by the log text
// and by how long it has been in this state, not by another enum value.
func listenStateLabel(st internalConnState) string {
	if st == stateConnected {
		return "connected"
	}
	return "listening"
}

// State returns the current snapshot.
func (e *listenEntry) State() SessionState {
	e.mu.Lock()
	defer e.mu.Unlock()

	// LastError is deliberately left empty. This end waits to be contacted and
	// never dials, so there is no attempt of its own that could have failed;
	// the side that dials in this arrangement is the far one, and its failures
	// are its own to report.
	//
	// The path is answered the same way as for a session this side opened, from
	// the live connection rather than the socket. That distinction does the work
	// here: this socket accepts both address families, so it cannot say which
	// one the peer used, while the connection carries the address the peer
	// arrived from.
	return SessionState{
		Name:       e.name,
		State:      listenStateLabel(e.intState),
		Transport:  transportListen,
		Since:      e.since,
		SSHPort:    e.sshPort,
		DockerPort: e.dockerPort,
		Path:       pathOf(e.current),
	}
}

// ControlCall copies the current control client under e.mu, releases the
// lock, and only then invokes fn — the identical shape dialEntry.ControlCall
// uses, so the two directions behave identically to any caller reaching them
// through the SessionEntry interface. The control client lives on this side
// of the connection in both directions (this end is always the gRPC client,
// whichever end opened the transport), so there is nothing direction-specific
// left to do here beyond which field and which state label are read.
func (e *listenEntry) ControlCall(ctx context.Context, fn func(ctx context.Context, c *control.Client) error) error {
	e.mu.Lock()
	cclient := e.controlClient
	st := e.intState
	e.mu.Unlock()

	if cclient == nil {
		return fmt.Errorf("server %q: no control client available (session=%s)", e.name, listenStateLabel(st))
	}

	callCtx, cancel := context.WithTimeout(ctx, DefaultControlCallTimeout)
	defer cancel()
	return fn(callCtx, cclient)
}

// Close stops the accept loop, drops any live connection, and releases the
// socket so the address can be rebound.
func (e *listenEntry) Close(err error) {
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

	// Closing the listener unblocks the accept loop.
	_ = e.ln.Close()
	<-e.runDone
	e.watchers.Wait()
	if e.t != nil {
		_ = e.t.Close()
	}
}

// failWaiters wakes anyone blocked in Get during shutdown, recording err so
// they can report why rather than merely waking with nothing to say — the
// same shape dialEntry uses for the same purpose (its dialErr/dialing pair).
func (e *listenEntry) failWaiters(err error) {
	e.mu.Lock()
	e.waitErr = err
	close(e.waiting)
	e.waiting = make(chan struct{})
	e.mu.Unlock()
}

// peerPrefix returns the short form of the peer's identity for logs. Only the
// prefix is ever emitted: it is enough to recognise a peer without putting a
// full key fingerprint into a log line.
func peerPrefix(conn transport.Conn) string {
	id, err := router.IdentityFromCerts(conn.PeerCertificates())
	if err != nil {
		return "unknown"
	}
	return id.Short()
}

var _ SessionEntry = (*listenEntry)(nil)
