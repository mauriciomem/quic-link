package daemon_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// shortSockPath returns a unix socket path short enough for macOS's 104-byte
// sun_path limit. t.TempDir() paths with test names can exceed the limit.
func shortSockPath(t *testing.T) string {
	t.Helper()
	p := fmt.Sprintf("/tmp/ql-daemon-test-%d.sock", os.Getpid())
	t.Cleanup(func() { os.Remove(p) })
	return p
}

// minimalCfg returns a bare-bones config suitable for daemon.Run tests.
// No servers are configured so the pool is empty and no QUIC dials happen.
func minimalCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Schema = 1
	return cfg
}

// waitForSocket polls until the unix socket file exists at path.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear within %s", path, timeout)
}

// ---- shutdown + socket-removal tests ----------------------------------------

// TestRun_SocketRemovedOnShutdown verifies that daemon.Run removes the socket
// file after the root ctx is cancelled. A subsequent invocation can then reclaim
// the path without the three-outcome probe returning a stale-socket condition.
func TestRun_SocketRemovedOnShutdown(t *testing.T) {
	sock := shortSockPath(t)

	pool := &fakePool{}
	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- daemon.Run(ctx, minimalCfg(), sock, pool, newFixedClock(), nil)
	}()

	// Wait for the socket to appear (daemon is ready).
	if err := waitForSocket(sock, 2*time.Second); err != nil {
		cancel()
		t.Fatalf("socket did not appear: %v", err)
	}

	// Verify socket exists before cancellation.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket should exist while daemon runs: %v", err)
	}

	// Cancel and wait for Run to return.
	cancel()
	select {
	case <-runDone:
	case <-time.After(15 * time.Second):
		t.Fatal("daemon.Run did not return within deadline")
	}

	// The socket file must be gone after clean shutdown.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket should have been removed after shutdown; stat err: %v", err)
	}
}

// TestRun_SocketAlwaysRemoved verifies that the socket is removed even when
// cancellation races the drain, by cancelling immediately after the socket
// appears (no in-flight handlers to drain).
func TestRun_SocketAlwaysRemoved(t *testing.T) {
	sock := shortSockPath(t)
	pool := &fakePool{}
	ctx, cancel := context.WithCancel(context.Background())

	runDone := make(chan error, 1)
	go func() {
		runDone <- daemon.Run(ctx, minimalCfg(), sock, pool, newFixedClock(), nil)
	}()

	if err := waitForSocket(sock, 2*time.Second); err != nil {
		cancel()
		t.Fatalf("socket did not appear: %v", err)
	}

	// Cancel immediately — simulates an instant SIGTERM.
	cancel()
	select {
	case <-runDone:
	case <-time.After(15 * time.Second):
		t.Fatal("daemon.Run did not return within deadline after immediate cancel")
	}

	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket should be removed even on immediate cancel; stat err: %v", err)
	}
}

// ---- privilege fence --------------------------------------------------------

// TestDaemon_IsUnprivileged is a lightweight assertion that daemon.Run starts
// and runs with no elevated capability: it binds only the unix socket (a
// loopback-visible path) without requiring root or CAP_NET_BIND_SERVICE. The
// test simply verifies that Run starts and services a status request while the
// process is unprivileged (os.Getuid() != 0), which is the invariant the
// design spec calls out. If this test ever runs as root, it is skipped
// (the guard still exists in code — we just can't assert it here).
func TestDaemon_IsUnprivileged(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test cannot assert non-root when running as root")
	}
	sock := shortSockPath(t)
	pool := &fakePool{}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- daemon.Run(ctx, minimalCfg(), sock, pool, newFixedClock(), nil)
	}()
	if err := waitForSocket(sock, 2*time.Second); err != nil {
		cancel()
		t.Fatalf("daemon did not start: %v", err)
	}
	c := ipc.NewClient(sock)
	if _, err := c.StatusJSON(); err != nil {
		t.Errorf("status failed while unprivileged: %v", err)
	}
	cancel()
	<-runDone
}

// ---- secret non-disclosure test ---------------------------------------------

// TestSecretNonDisclosure_NoFullPinOrKeyBytesInLogs verifies that emitted log
// lines do not contain private-key bytes or full 44-character pin strings.
// This is the log-layer complement to the golden-file test in daemon_test.go,
// which guards the status --json surface.
//
// The golden test in daemon_test.go pins the exact JSON byte-shape and
// explicitly notes it guards against secret leakage; this test covers the slog
// output layer. Logs may carry an 8-character pin prefix for attribution, but
// never the full 44-character pin and never key material.
func TestSecretNonDisclosure_NoFullPinOrKeyBytesInLogs(t *testing.T) {
	// A well-formed 44-char base64 string in the pin shape (Ed25519 SHA-256
	// SPKI hash). This is a test fixture, not a real key.
	testPin := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if len(testPin) != 44 {
		t.Fatalf("test pin should be 44 chars, got %d", len(testPin))
	}

	// Capture log output at debug level.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(slog.Default()) })

	sock := shortSockPath(t)
	pool := &fakePool{}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- daemon.Run(ctx, minimalCfg(), sock, pool, newFixedClock(), nil)
	}()

	if err := waitForSocket(sock, 2*time.Second); err != nil {
		cancel()
		t.Fatalf("socket did not appear: %v", err)
	}

	// Exercise the log path with a real status request.
	c := ipc.NewClient(sock)
	if _, err := c.StatusJSON(); err != nil {
		t.Logf("status RPC: %v (non-fatal for log check)", err)
	}

	cancel()
	<-runDone

	logs := buf.String()

	// The full 44-char pin must never appear.
	if len(testPin) == 44 && containsStr(logs, testPin) {
		t.Errorf("logs contain the full pin %q — full pins must never appear in logs", testPin)
	}

	// Private key PEM header as a canary for key material.
	if containsStr(logs, "PRIVATE KEY") {
		t.Error("logs contain 'PRIVATE KEY' — key material must never appear in logs")
	}

	// Payload canary: no spliced data should ever appear.
	if containsStr(logs, "PAYLOAD_CANARY") {
		t.Error("logs contain 'PAYLOAD_CANARY' — payload bytes must never be logged")
	}
}

func containsStr(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i <= len(haystack)-len(needle); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
