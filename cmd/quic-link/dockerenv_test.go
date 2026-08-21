package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// stubStatusProvider is a minimal ipc.StatusProvider returning fixed JSON.
type stubStatusProvider struct {
	data []byte
}

func (s *stubStatusProvider) StatusJSON() ([]byte, error) { return s.data, nil }

// withDaemonSocketEnv points the daemon socket resolution at a test socket by
// setting XDG_RUNTIME_DIR to a directory containing a "quic-link" subdir with
// a pre-placed daemon.sock — i.e. it bypasses socketPath's own directory
// creation by pre-creating the expected layout, then symlinking/copying is
// unnecessary because ipc.Server already bound the real path there.
//
// Simpler: instead of trying to make daemonSocketPath resolve to an arbitrary
// temp path, this test starts the server AT the path daemonSocketPath would
// itself compute for a given XDG_RUNTIME_DIR, by setting XDG_RUNTIME_DIR to a
// fresh temp dir first and asking daemonSocketPath for the path before
// starting the server there.
func withDaemonSocketEnv(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
}

// shortTempDir returns a private directory whose path is short enough to hold a
// unix socket, and removes it when the test finishes.
//
// t.TempDir cannot be used for this. It builds its path from TMPDIR and the
// test's own name, and a unix socket address is limited to 104 bytes on macOS —
// the smaller of the two platform limits, and the one this project enforces
// everywhere. The longest test name here contributes 97 bytes on its own, which
// leaves room for a TMPDIR of about seven characters. On Linux TMPDIR is
// normally /tmp and the whole path fits with three bytes to spare; on macOS it
// is a per-user directory under /var/folders that is roughly fifty characters,
// and the socket cannot be bound at all. The failure is a bare
// "bind: invalid argument" that says nothing about length, so it is worth not
// rediscovering.
//
// os.MkdirTemp with an empty first argument uses the same TMPDIR and would have
// the same problem, so /tmp is named explicitly. That is the one directory both
// platforms guarantee, and only test code depends on it: the daemon itself
// resolves its socket through XDG_RUNTIME_DIR, then TMPDIR with a length check,
// then /tmp, and that logic is what these tests exercise rather than replace.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ql-test-")
	if err != nil {
		t.Fatalf("creating a short temp dir for a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestDockerEnv_NoDaemon_Exit3_NoStdout(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	root := newRootCmd()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "docker-env", "server1"})
	err := root.ExecuteContext(context.Background())

	if err == nil {
		t.Fatal("expected an error when no daemon is running")
	}
	if got := exitCode(err); got != 3 {
		t.Errorf("exitCode = %d, want 3 (daemon absent)", got)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure (safe eval no-op), got %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("expected a human message on stderr")
	}
}

func TestDockerEnv_ZeroPort_Exit3_NoStdout(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	sockPath, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	statusJSON := `{"schema":1,"servers":[{"name":"server1","session":"connected","transport":"dial","since_ms":10,"local_ports":{"ssh":42000,"docker":0}}]}`
	startServerAtPath(t, sockPath, statusJSON)

	root := newRootCmd()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "docker-env", "server1"})
	runErr := root.ExecuteContext(context.Background())

	if runErr == nil {
		t.Fatal("expected an error for a zero docker port")
	}
	if got := exitCode(runErr); got != 3 {
		t.Errorf("exitCode = %d, want 3 (zero-port rule), err=%v", got, runErr)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on the zero-port path, got %q", stdout.String())
	}
}

// TestDockerEnv_DisabledServer_ExplainsWhy pins the fix for a defect found by
// empirical check: before the fix, a disabled server (session="disabled" in
// the daemon's live status) fell into the generic "not connected
// (session=disabled)" branch, which never tells the user WHY or what to do
// about it. This asserts the same explicit remedy message the ssh and stdio
// verbs already give for the identical config state.
func TestDockerEnv_DisabledServer_ExplainsWhy(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
enabled = false
`)
	sockPath, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	statusJSON := `{"schema":1,"servers":[{"name":"server1","session":"disabled","transport":"dial","since_ms":10,"local_ports":{"ssh":0,"docker":0}}]}`
	startServerAtPath(t, sockPath, statusJSON)

	root := newRootCmd()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "docker-env", "server1"})
	runErr := root.ExecuteContext(context.Background())

	if exitCode(runErr) != 3 {
		t.Errorf("exitCode = %d, want 3 (disabled server), err=%v", exitCode(runErr), runErr)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty for a disabled server, got %q", stdout.String())
	}
	wantMsg := `server "server1" is disabled; set enabled = true in the config to use it`
	if !strings.Contains(stderr.String(), wantMsg) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), wantMsg)
	}
}

func TestDockerEnv_NotConnected_Exit3_NoStdout(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	sockPath, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	statusJSON := `{"schema":1,"servers":[{"name":"server1","session":"connecting","transport":"dial","since_ms":10,"local_ports":{"ssh":42000,"docker":42001}}]}`
	startServerAtPath(t, sockPath, statusJSON)

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetArgs([]string{"--config", path, "docker-env", "server1"})
	runErr := root.ExecuteContext(context.Background())

	if exitCode(runErr) != 3 {
		t.Errorf("exitCode = %d, want 3 (not connected), err=%v", exitCode(runErr), runErr)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty when not connected, got %q", stdout.String())
	}
}

func TestDockerEnv_Connected_PrintsContractLine(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	sockPath, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	statusJSON := `{"schema":1,"servers":[{"name":"server1","session":"connected","transport":"dial","since_ms":10,"local_ports":{"ssh":42000,"docker":42001}}]}`
	startServerAtPath(t, sockPath, statusJSON)

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetArgs([]string{"--config", path, "docker-env", "server1"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("docker-env: %v", err)
	}

	want := "export DOCKER_HOST=tcp://127.0.0.1:42001\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q (CONTRACT line)", stdout.String(), want)
	}
}

// startServerAtPath starts a real ipc.Server at an exact pre-computed path
// (rather than a random one), so daemonSocketPath's own resolution — which
// docker-env calls internally — finds it.
func startServerAtPath(t *testing.T, sock, statusJSON string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	srv := ipc.NewServer(sock, &stubStatusProvider{data: []byte(statusJSON)}, nil)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		os.Remove(sock)
	})
}
