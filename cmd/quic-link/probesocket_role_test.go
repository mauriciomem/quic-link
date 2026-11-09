/**
 * @spec-handoff
 * @interface
 *   func probeSocketForRole(sock, role string) (canReclaim bool, err error)
 *   // probeSocket(sock) remains and behaves as probeSocketForRole(sock, "daemon").
 *   // errOwnerRunningType / errSquatterType gain a role field; role == "" is
 *   // treated as "daemon" by their Error() methods.
 * @behavior
 *   - Same three-outcome classification as probeSocket, unchanged:
 *       live conforming owner -> (false, *errOwnerRunningType)  [exit 3]
 *       no listener / stale   -> (true,  nil)
 *       garbled squatter      -> (false, *errSquatterType)      [exit 2]
 *   - The role is threaded into the returned error's text:
 *       probeSocketForRole(sock, "agent") error text contains "agent" and,
 *       for the owner case, does NOT contain "daemon" (the "daemon owner
 *       already running" label is derived from the role).
 *   - The squatter message carries no "daemon" label, so a non-daemon role
 *     adds a role label (contains "agent"); the "daemon" / "" role text has
 *     no label.
 *   - probeSocketForRole(sock, "daemon") returns the byte-identical error text
 *     that probeSocket(sock) returns for the same socket (wrapper equivalence).
 *   - Exit-code mapping (exitCodeForError) is role-independent: owner -> 3,
 *     squatter -> 2.
 * @edge-cases
 *   - Absent socket: role does not change the outcome (true, nil).
 *   - Existing tests that build &errOwnerRunningType{sock: x} /
 *     &errSquatterType{sock: x, reason: y} without a role must keep compiling
 *     and keep producing today's exact text (zero-value role == "daemon").
 *   - The role argument must be honored: a probeSocketForRole that ignores
 *     it would fail the agent-label assertions.
 * @see ./daemoncmd.go (probeSocket, errOwnerRunningType, errSquatterType)
 * @see ./single_instance_test.go (startTestDaemon and the three probeSocket outcome tests)
 */
package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// roleTestSockPath returns a short, unique unix socket path (macOS sun_path
// limit is 104 bytes) in a private temp dir, so every subtest is independent
// of the pid-keyed path shortSockPathForCmd hands out. The path deliberately
// contains neither "agent" nor "daemon", so role labels asserted below can
// only come from the role argument, never from the socket path.
func roleTestSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ql-r-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// startGarbledSquatter makes sock look like it is held by a process that is not
// a quic-link daemon: it accepts connections, immediately writes a line of
// non-protocol bytes, then keeps reading (and discarding) until the client
// hangs up or the test ends.
//
// The connection must stay open on purpose. If the squatter wrote and closed at
// once, the outcome of a probe would depend on scheduling: the client's request
// write could hit the already-closed peer ("probe write: broken pipe") or land
// in the socket buffer and be followed by a read of the garbage ("probe read:
// unexpected frame version 0x4e"). Two consecutive probes of the same socket
// could then report different error texts. Holding the connection open makes
// the write always succeed, so every probe fails on the read side with the same
// frame-version error.
//
// The listener, every accepted connection and all handler goroutines are torn
// down by t.Cleanup. Listening happens before this returns, so the kernel
// queues connects made right away; no startup sleep is needed.
func startGarbledSquatter(t *testing.T, sock string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("squatter listen: %v", err)
	}

	var (
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			conns = append(conns, conn)
			wg.Add(1)
			mu.Unlock()
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = c.Write([]byte("NOT A QUIC-LINK DAEMON\n"))
				_, _ = io.Copy(io.Discard, c) // returns on client close or cleanup
			}(conn)
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		closed = true
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
}

// TestProbeSocketForRole_ThreadsRoleThroughClassification proves the role
// parameter of probeSocketForRole is real, not decorative: the same
// owner/absent/squatter classification probeSocket performs is preserved, and
// a non-"daemon" role is observable in the returned error while the "daemon"
// role stays byte-identical to probeSocket.
func TestProbeSocketForRole_ThreadsRoleThroughClassification(t *testing.T) {
	t.Run("live owner: agent role labels the error, daemon role matches probeSocket", func(t *testing.T) {
		sock := roleTestSockPath(t)
		cancel, done := startTestDaemon(t, sock)
		defer func() {
			cancel()
			<-done
		}()

		canReclaim, agentErr := probeSocketForRole(sock, "agent")
		if canReclaim {
			t.Error("a live owner's socket must not be reclaimable")
		}
		var owner *errOwnerRunningType
		if !errors.As(agentErr, &owner) {
			t.Fatalf("live owner must yield *errOwnerRunningType, got %T: %v", agentErr, agentErr)
		}
		if code := exitCodeForError(agentErr); code != 3 {
			t.Errorf("live-owner error must map to exit 3 regardless of role, got %d", code)
		}
		if !strings.Contains(agentErr.Error(), "agent") {
			t.Errorf("agent-role owner error must name the role %q, got: %v", "agent", agentErr)
		}
		if strings.Contains(agentErr.Error(), "daemon") {
			t.Errorf("agent-role owner error must not carry the hardcoded %q label, got: %v", "daemon", agentErr)
		}

		// The same socket, probed as the daemon role, must read differently
		// and be byte-identical to what the one-argument wrapper reports.
		_, daemonErr := probeSocketForRole(sock, "daemon")
		if daemonErr == nil {
			t.Fatal("daemon-role probe of a live owner must return an error, got nil")
		}
		if !strings.Contains(daemonErr.Error(), "daemon") {
			t.Errorf("daemon-role owner error must name %q, got: %v", "daemon", daemonErr)
		}
		if daemonErr.Error() == agentErr.Error() {
			t.Errorf("role must change the owner error text; both roles produced: %v", daemonErr)
		}
		_, wrapperErr := probeSocket(sock)
		if wrapperErr == nil || wrapperErr.Error() != daemonErr.Error() {
			t.Errorf("probeSocketForRole(sock, %q) must equal probeSocket(sock):\n  role:    %v\n  wrapper: %v",
				"daemon", daemonErr, wrapperErr)
		}
	})

	t.Run("absent socket: reclaimable with no error for any role", func(t *testing.T) {
		sock := roleTestSockPath(t) // nothing listens here

		for _, role := range []string{"agent", "daemon"} {
			canReclaim, err := probeSocketForRole(sock, role)
			if err != nil {
				t.Errorf("role %q: absent socket must yield nil error, got: %v", role, err)
			}
			if !canReclaim {
				t.Errorf("role %q: absent socket must be reclaimable", role)
			}
		}
	})

	t.Run("squatter: agent role labels the error, daemon role matches probeSocket", func(t *testing.T) {
		sock := roleTestSockPath(t)

		startGarbledSquatter(t, sock)

		canReclaim, agentErr := probeSocketForRole(sock, "agent")
		if canReclaim {
			t.Error("a squatter-held socket must not be reclaimable")
		}
		var squatter *errSquatterType
		if !errors.As(agentErr, &squatter) {
			t.Fatalf("squatter must yield *errSquatterType, got %T: %v", agentErr, agentErr)
		}
		if code := exitCodeForError(agentErr); code != 2 {
			t.Errorf("squatter error must map to exit 2 regardless of role, got %d", code)
		}
		if !strings.Contains(agentErr.Error(), "agent") {
			t.Errorf("agent-role squatter error must name the role %q, got: %v", "agent", agentErr)
		}

		_, daemonErr := probeSocketForRole(sock, "daemon")
		if daemonErr == nil {
			t.Fatal("daemon-role probe of a squatter must return an error, got nil")
		}
		if daemonErr.Error() == agentErr.Error() {
			t.Errorf("role must change the squatter error text; both roles produced: %v", daemonErr)
		}
		_, wrapperErr := probeSocket(sock)
		if wrapperErr == nil || wrapperErr.Error() != daemonErr.Error() {
			t.Errorf("probeSocketForRole(sock, %q) must equal probeSocket(sock):\n  role:    %v\n  wrapper: %v",
				"daemon", daemonErr, wrapperErr)
		}

		// A squatter's socket file must never be removed by the probe.
		if _, statErr := os.Stat(sock); os.IsNotExist(statErr) {
			t.Error("socket must NOT be removed when a squatter is detected")
		}
	})
}
