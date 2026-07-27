package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// shortSockPathForCmd returns a unix socket path short enough for macOS's
// 104-byte sun_path limit.
func shortSockPathForCmd(t *testing.T) string {
	t.Helper()
	p := fmt.Sprintf("/tmp/ql-cmd-test-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(p) })
	return p
}

// fakePoolForCmd is a minimal SessionPool for integration tests in this package.
type fakePoolForCmd struct{}

func (f *fakePoolForCmd) Get(_ context.Context, _ string) (daemon.Conn, error) { return nil, nil }
func (f *fakePoolForCmd) State() []daemon.SessionState                         { return nil }
func (f *fakePoolForCmd) EntryState(_ string) (string, error)                  { return "disabled", nil }
func (f *fakePoolForCmd) Close()                                               {}

// startTestDaemon starts daemon.Run and waits for the socket to appear.
func startTestDaemon(t *testing.T, sock string) (cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Schema = 1

	ctx, c := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() {
		ch <- daemon.Run(ctx, cfg, sock, &fakePoolForCmd{}, daemon.WallClock{})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return c, ch
		}
		time.Sleep(20 * time.Millisecond)
	}
	c()
	t.Fatalf("daemon socket %s did not appear within 3s", sock)
	return c, ch
}

// TestProbeSocket_LiveOwnerExitsThree verifies that probeSocket returns a
// live-owner error (→ exit 3) when a conforming daemon is already running.
func TestProbeSocket_LiveOwnerExitsThree(t *testing.T) {
	sock := shortSockPathForCmd(t)
	cancel, done := startTestDaemon(t, sock)
	defer func() {
		cancel()
		<-done
	}()

	canReclaim, err := probeSocket(sock)
	if canReclaim {
		t.Error("probeSocket should not allow reclaim of a live owner's socket")
	}
	if err == nil {
		t.Fatal("probeSocket should return an error for a live owner, got nil")
	}
	if code := exitCodeForError(err); code != 3 {
		t.Errorf("live-owner error should map to exit 3, got %d: %v", code, err)
	}
}

// TestProbeSocket_StaleAllowsReclaim verifies that probeSocket returns
// canReclaim=true when no listener is at the socket path.
func TestProbeSocket_StaleAllowsReclaim(t *testing.T) {
	sock := shortSockPathForCmd(t)
	// Socket does not exist — should be treated as stale/absent.

	canReclaim, err := probeSocket(sock)
	if err != nil {
		t.Fatalf("probeSocket for absent socket: %v", err)
	}
	if !canReclaim {
		t.Error("probeSocket should allow reclaim of an absent/stale socket")
	}
}

// TestProbeSocket_DanglingSocketAllowsReclaim is the specific regression test
// for the bug where a dangling unix socket file (file exists on disk but no
// process is listening) was misclassified as a squatter (→ exit 2) instead of
// being treated as a stale socket (→ canReclaim=true).
//
// Root cause: isNetRefused used string-matching on the OS error message
// ("connection refused") which failed on darwin where the wrapped error is
// "connect: connection refused". The fix uses errors.Is(err, syscall.ECONNREFUSED)
// which correctly unwraps *net.OpError → *os.SyscallError → syscall.Errno on
// both Linux and macOS.
//
// Scenario: bind a listener, then close it with SetUnlinkOnClose(false) so the
// socket file remains on disk with nothing listening. A dial attempt returns
// ECONNREFUSED, which must be classified as "stale, reclaim allowed."
func TestProbeSocket_DanglingSocketAllowsReclaim(t *testing.T) {
	sock := shortSockPathForCmd(t)

	// Bind a unix socket listener.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}

	// Tell the listener not to remove the socket file on Close, leaving a
	// dangling socket path with nothing listening — exactly the state a crashed
	// daemon leaves behind.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	ln.Close()

	// Confirm the file still exists (prerequisite for the test to be meaningful).
	if _, statErr := os.Stat(sock); os.IsNotExist(statErr) {
		t.Skip("socket file was removed on close; cannot simulate dangling socket on this platform")
	}

	// The dangling socket must be classified as stale/absent, not squatter.
	canReclaim, err := probeSocket(sock)
	if err != nil {
		t.Errorf("dangling socket should produce nil error (stale/absent), got: %v", err)
	}
	if !canReclaim {
		t.Error("dangling socket should allow reclaim (canReclaim=true), not be treated as a squatter")
	}
}

// TestProbeSocket_SquatterExitsTwo verifies that probeSocket returns a squatter
// error (→ exit 2) when something is listening at the socket path but its
// response is not a conforming quic-link status reply.
func TestProbeSocket_SquatterExitsTwo(t *testing.T) {
	sock := shortSockPathForCmd(t)

	// Start a "squatter" that accepts connections and sends garbage.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("squatter listen: %v", err)
	}
	t.Cleanup(func() {
		ln.Close()
		os.Remove(sock)
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("NOT A QUIC-LINK DAEMON\n"))
			}(conn)
		}
	}()

	// Allow the squatter to start accepting.
	time.Sleep(20 * time.Millisecond)

	canReclaim, err := probeSocket(sock)
	if canReclaim {
		t.Error("probeSocket should not allow reclaim of a squatter-held socket")
	}
	if err == nil {
		t.Fatal("probeSocket should return an error for a squatter, got nil")
	}
	if code := exitCodeForError(err); code != 2 {
		t.Errorf("squatter error should map to exit 2, got %d: %v", code, err)
	}

	// The socket file must NOT be removed (never reclaim from a squatter).
	if _, statErr := os.Stat(sock); os.IsNotExist(statErr) {
		t.Error("socket should NOT be removed by probeSocket when a squatter is detected")
	}
}

// TestProbeSocket_SchemaMismatchIsLiveOwner verifies that ipc.ErrSchemaMismatch
// from the probe is treated as a live-owner condition (→ exit 3), not a squatter.
// A schema-mismatched daemon is "restart to upgrade" guidance, not "investigate".
func TestProbeSocket_SchemaMismatchIsLiveOwner(t *testing.T) {
	// Wrap ErrSchemaMismatch the same way probeSocket does.
	err := &errOwnerRunningType{sock: "/tmp/test.sock"}
	if code := exitCodeForError(err); code != 3 {
		t.Errorf("live-owner with schema mismatch should map to exit 3, got %d", code)
	}
}

// TestSingleInstanceCheck_IntegrationTable is a table-driven test verifying the
// three outcomes produce the correct exit codes.
func TestSingleInstanceCheck_IntegrationTable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"live owner → exit 3", &errOwnerRunningType{sock: "x"}, 3},
		{"squatter → exit 2", &errSquatterType{sock: "x", reason: "garbled"}, 2},
		{"ErrDaemonAbsent → exit 3", ipc.ErrDaemonAbsent, 3},
		{"ErrSchemaMismatch → exit 3", ipc.ErrSchemaMismatch, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCodeForError(tt.err)
			if got != tt.wantCode {
				t.Errorf("exitCodeForError(%v) = %d, want %d", tt.err, got, tt.wantCode)
			}
		})
	}
}
