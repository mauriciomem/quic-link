// Package edge owns the local loopback listeners for the daemon's lifetime.
// Each enabled server gets one localPortEdge, which holds a bound TCP listener
// for the ssh target and a bound TCP listener for the docker target. Accepted
// connections are spliced directly to a QUIC stream via tunnel.DoAttach without
// an additional ack round-trip (the local application already connects directly
// to the port — no IPC ack is needed).
//
// Port acquisition uses a coherent block strategy: both listeners are acquired
// together, stepping in ten-port increments, so the two services for a server
// always occupy a predictable adjacent pair. The listeners are held open for the
// daemon's lifetime (hold-the-listener pattern), eliminating the TOCTOU race
// that afflicts the probe-then-bind approach used by the foreground connect verb.
package edge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ConnSource provides a live pooled connection for a named server. The daemon's
// poolAttachAdapter satisfies this interface alongside ipc.AttachPool.OpenConn.
type ConnSource interface {
	// OpenConn returns a live pooled connection for server, bounded-waiting on
	// an in-flight reconnect. Returns the peer pin-prefix and an error if the
	// session is not ready. It never dials a new connection.
	OpenConn(ctx context.Context, server string) (conn tunnel.StreamConn, pinPrefix string, err error)
}

// portProbeBlocks is the maximum number of ten-port blocks tried before giving
// up when acquiring a port pair. With base ports near 42000, ten blocks covers
// 42000–42100 which is well within ephemeral range.
const portProbeBlocks = 10

// openConnReadyTimeout is the maximum time an edge accept loop waits for the
// pool to provide a live connection when a reconnect is in progress. The value
// matches the IPC attach timeout so both entry points behave identically.
const openConnReadyTimeout = 5 * time.Second

// PortAllocator acquires coherent (ssh, docker) listener pairs for a server.
type PortAllocator struct{}

// AcquirePair binds the ssh and docker listeners for server as a coherent
// block, starting at the base ports derived from the server name and config
// overrides, stepping by ten-port increments on any clash. Both listeners are
// acquired simultaneously (never close-and-rebind), eliminating TOCTOU.
//
// On partial acquisition (ssh binds, docker clashes past the block budget) the
// held ssh listener is closed and the error is returned. Callers must close
// the returned listeners when done.
func (PortAllocator) AcquirePair(server string, overrides map[string]int) (sshLn, dockerLn net.Listener, err error) {
	sshBase, dockerBase := config.LocalPorts(server, overrides)

	for i := range portProbeBlocks {
		off := i * 10
		sp := sshBase + off
		dp := dockerBase + off

		l1, e1 := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", sp))
		if e1 != nil {
			continue
		}
		l2, e2 := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", dp))
		if e2 != nil {
			_ = l1.Close()
			continue
		}
		return l1, l2, nil
	}
	return nil, nil, fmt.Errorf("edge: no free port pair for %q near ssh=%d docker=%d after %d blocks",
		server, sshBase, dockerBase, portProbeBlocks)
}

// LocalPortEdge holds the two bound listeners for a single server and runs
// one accept-loop goroutine per listener. Accepted TCP connections are spliced
// directly to QUIC streams via tunnel.DoAttach, bypassing the IPC ack
// round-trip (raw local clients never receive an ack).
type LocalPortEdge struct {
	server string
	sshLn  net.Listener
	dkrLn  net.Listener
	src    ConnSource

	wg sync.WaitGroup
}

// NewLocalPortEdge constructs and starts a LocalPortEdge. The two accept-loop
// goroutines begin immediately; Close must be called to stop them.
func NewLocalPortEdge(ctx context.Context, server string, sshLn, dockerLn net.Listener, src ConnSource) *LocalPortEdge {
	e := &LocalPortEdge{
		server: server,
		sshLn:  sshLn,
		dkrLn:  dockerLn,
		src:    src,
	}
	e.wg.Add(2)
	go e.acceptLoop(ctx, sshLn, "ssh")
	go e.acceptLoop(ctx, dockerLn, "docker")
	return e
}

// Close closes both listeners (unblocking Accept) and waits for all accept and
// splice goroutines to exit. goleak-clean.
func (e *LocalPortEdge) Close() {
	_ = e.sshLn.Close()
	_ = e.dkrLn.Close()
	e.wg.Wait()
}

// acceptLoop accepts TCP connections from ln and splices each to a QUIC stream
// for target. Each accepted conn gets its own goroutine so the loop keeps
// accepting. DoAttach closes the conn when the splice ends.
func (e *LocalPortEdge) acceptLoop(ctx context.Context, ln net.Listener, target string) {
	defer e.wg.Done()

	// Watch ctx: when the daemon shuts down, close the listener so Accept
	// unblocks. The goroutine below exits when the acceptLoop exits (because
	// a closed ln.Close() makes the ctx-wait goroutine unnecessary — both paths
	// converge on ln.Close()). Track it with the WaitGroup so Close() joins it.
	done := make(chan struct{})
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			// A closed listener is the clean shutdown signal.
			return
		}
		e.wg.Add(1)
		go e.splice(ctx, tcpConn, target)
	}
}

// splice obtains a live pooled connection and runs DoAttach for tcpConn. The
// relayAck is nil because raw local clients connect directly to the port — they
// do not speak the IPC protocol and expect no ack frame.
func (e *LocalPortEdge) splice(ctx context.Context, tcpConn net.Conn, target string) {
	defer e.wg.Done()
	defer tcpConn.Close()

	octx, cancel := context.WithTimeout(ctx, openConnReadyTimeout)
	poolConn, pinPrefix, err := e.src.OpenConn(octx, e.server)
	cancel()
	if err != nil {
		slog.Warn("edge: pool not ready; dropping accepted connection",
			"role", "daemon",
			"server", e.server,
			"target", target,
			"err", err,
		)
		return
	}

	reqid := tunnel.NewReqID()
	start := time.Now()
	tunnel.LogAttach(e.server, target, reqid, pinPrefix, start, false)
	defer tunnel.LogAttach(e.server, target, reqid, pinPrefix, start, true)

	// relayAck is nil: raw TCP clients on a local port get no IPC ack frame.
	if err := tunnel.DoAttach(ctx, poolConn, tcpConn, target, reqid, nil); err != nil {
		slog.Debug("edge: splice ended", "role", "daemon",
			"server", e.server, "target", target, "err", err)
	}
}
