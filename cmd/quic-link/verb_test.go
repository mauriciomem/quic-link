package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// ---- helpers ----------------------------------------------------------------

// writeTestConfig writes a TOML config to a temp file and returns its path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeTestConfig: %v", err)
	}
	return path
}

// mustTestPin generates a fresh key and returns its canonical pin string.
func mustTestPin(t *testing.T) string {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	return pin
}

// runVerbCtx executes the cobra tree with the given context and args.
func runVerbCtx(ctx context.Context, args []string) error {
	return executeRoot(ctx, args)
}

// runVerb executes the cobra tree with a background context.
// Use runVerbCtx for tests that need to cancel a long-running verb.
func runVerb(args []string) error {
	return runVerbCtx(context.Background(), args)
}

// exitCode maps an error to the process exit code that main() would return.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	return exitCodeForError(err)
}

// unsetQLEnv removes all QUIC_LINK_* environment variables for the duration of
// a test so prior env state doesn't bleed in.
func unsetQLEnvForTest(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(k, "QUIC_LINK_") {
			old := os.Getenv(k)
			_ = os.Unsetenv(k)
			kk := k
			t.Cleanup(func() { _ = os.Setenv(kk, old) })
		}
	}
}

// ---- enabledServers helper --------------------------------------------------

func TestEnabledServersHelper(t *testing.T) {
	pin := mustTestPin(t)

	t.Run("nil_enabled_counts_as_enabled", func(t *testing.T) {
		path := writeTestConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
`)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		got := enabledServers(cfg.Servers)
		if _, ok := got["s1"]; !ok {
			t.Error("s1 with nil Enabled should be in enabled map")
		}
	})

	t.Run("explicit_false_excluded", func(t *testing.T) {
		path := writeTestConfig(t, `
schema = 1
[servers.s1]
addr    = "1.2.3.4:7443"
pin     = "`+pin+`"
enabled = false
`)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		got := enabledServers(cfg.Servers)
		if _, ok := got["s1"]; ok {
			t.Error("s1 with enabled=false should NOT be in enabled map")
		}
	})
}

// ---- sortStrings ------------------------------------------------------------

func TestSortStrings(t *testing.T) {
	ss := []string{"banana", "apple", "cherry"}
	sortStrings(ss)
	want := []string{"apple", "banana", "cherry"}
	for i := range want {
		if ss[i] != want[i] {
			t.Errorf("sortStrings[%d] = %q, want %q", i, ss[i], want[i])
		}
	}
}

// ---- bindFreePort -----------------------------------------------------------

func TestBindFreePort(t *testing.T) {
	t.Run("finds_a_port", func(t *testing.T) {
		port, err := bindFreePort("127.0.0.1", 40100, 10)
		if err != nil {
			t.Fatalf("bindFreePort: %v", err)
		}
		if port < 40100 || port >= 40110 {
			t.Errorf("port %d out of expected range [40100, 40110)", port)
		}
	})

	t.Run("zero_window_returns_error", func(t *testing.T) {
		_, err := bindFreePort("127.0.0.1", 40200, 0)
		if err == nil {
			t.Fatal("expected error for zero window, got nil")
		}
	})
}

// ---- connect resolution tests -----------------------------------------------
//
// Resolution errors → exit 2. Transport errors → exit 1 (or 4 for auth).
// We use a loopback address where nothing listens so the transport fails fast.

// TestConnectPositionalServerNotFound verifies that naming a server that is
// not in the config is a usage error (exit 2).
func TestConnectPositionalServerNotFound(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "connect", "no_such_server"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for unknown server name, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "no_such_server") {
		t.Errorf("error should name the missing server, got: %v", err)
	}
}

// TestConnectPositionalServerResolved verifies that a valid positional SERVER
// resolves addr and pin from config. The test expects a transport failure
// (exit 1 or 4), not a resolution failure (exit 2).
// We cancel the context quickly so the local TCP listeners don't block forever.
func TestConnectPositionalServerResolved(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:19999"
pin  = "`+pin+`"
`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so tunnel.Connect returns quickly
	err := runVerbCtx(ctx, []string{"--config", path, "connect", "server1"})
	code := exitCode(err)
	if code == 2 {
		t.Errorf("expected transport error (exit 1 or 4), got exit 2 (resolution error): %v", err)
	}
}

// TestConnectDefaultToSole verifies that when exactly one enabled server
// exists and no SERVER arg or --server flag is given, that server is used.
func TestConnectDefaultToSole(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.only]
addr = "127.0.0.1:19998"
pin  = "`+pin+`"
`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runVerbCtx(ctx, []string{"--config", path, "connect"})
	code := exitCode(err)
	if code == 2 {
		t.Errorf("expected transport error (not resolution), got exit 2: %v", err)
	}
}

// TestConnectAmbiguousServers verifies that two enabled servers with no
// positional arg is a usage error (exit 2).
func TestConnectAmbiguousServers(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.alpha]
addr = "127.0.0.1:7001"
pin  = "`+pin+`"

[servers.beta]
addr = "127.0.0.1:7002"
pin  = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "connect"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for ambiguous servers, got %d: %v", exitCode(err), err)
	}
}

// TestConnectDisabledServer verifies that explicitly naming a disabled server
// is a usage error (exit 2).
func TestConnectDisabledServer(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.off]
addr    = "127.0.0.1:7443"
pin     = "`+pin+`"
enabled = false
`)
	err := runVerb([]string{"--config", path, "connect", "off"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for disabled server, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("error should mention 'disabled', got: %v", err)
	}
}

// TestConnectReverseServer verifies that a server with listen= (reverse mode)
// yields the "not yet supported; later phase" message and exit 2.
func TestConnectReverseServer(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.rev]
listen = ":7443"
pin    = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "connect", "rev"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for reverse-mode server, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "later phase") {
		t.Errorf("error should mention 'later phase', got: %v", err)
	}
}

// TestConnectFlagOnlyNoConfig verifies that --server + --pin flags work with
// no config file, failing at the transport layer (exit 1) not at resolution
// (exit 2).
func TestConnectFlagOnlyNoConfig(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	// Point HOME at a temp dir so the default config path has no file.
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runVerbCtx(ctx, []string{
		"connect",
		"--server", "127.0.0.1:19997",
		"--pin", pin,
	})
	code := exitCode(err)
	if code == 2 {
		t.Errorf("flag-only connect should not fail at resolution (exit 2): %v", err)
	}
}

// ---- ping resolution tests --------------------------------------------------

// TestPingReverseServer verifies that pinging a reverse-mode server gives
// exit 2 with the "later phase" message.
func TestPingReverseServer(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.rev]
listen = ":7443"
pin    = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "ping", "rev"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for reverse-mode ping server, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "later phase") {
		t.Errorf("error should mention 'later phase', got: %v", err)
	}
}

// TestPingFlagOnly verifies that --server + --pin flags work with no config
// file, failing at transport (exit 1) not at resolution (exit 2).
func TestPingFlagOnly(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runVerbCtx(ctx, []string{
		"ping",
		"--server", "127.0.0.1:19996",
		"--pin", pin,
		"--count", "1",
	})
	code := exitCode(err)
	if code == 2 {
		t.Errorf("flag-only ping should not fail at resolution (exit 2): %v", err)
	}
}

// ---- agent resolution tests -------------------------------------------------

// TestAgentEmptyAuthorizedClients verifies that starting agent with no
// authorized clients (neither flags nor config) is exit 2.
func TestAgentEmptyAuthorizedClients(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("HOME", t.TempDir())

	path := writeTestConfig(t, `
schema = 1
[agent]
listen = "127.0.0.1:0"
authorized_clients = []
`)
	err := runVerb([]string{"--config", path, "agent"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for empty authorized_clients, got %d: %v", exitCode(err), err)
	}
}

// TestAgentFlagOnlyNoConfig verifies that flag-only agent works with no config
// file (resolution succeeds; we cancel the context immediately to avoid
// actually running a QUIC server during the test).
func TestAgentFlagOnlyNoConfig(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	pin := mustTestPin(t)

	// Generate a real key at the default path within the temp HOME.
	keyPath := filepath.Join(tmp, ".config", "quic-link", "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := runVerb([]string{"keygen", "--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to avoid blocking

	root := newRootCmd()
	root.SetArgs([]string{
		"agent",
		"--listen", "127.0.0.1:0",
		"--key", keyPath,
		"--authorized-client", pin,
	})
	err := root.ExecuteContext(ctx)
	code := exitCode(err)
	if code == 2 {
		t.Errorf("flag-only agent should not fail at resolution (exit 2): %v", err)
	}
}

// TestAgentReadsFromConfig verifies that [agent] in the config file provides
// listen and authorized_clients without requiring flags.
func TestAgentReadsFromConfig(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	pin := mustTestPin(t)

	// Generate a key so agentRun can load it.
	keyPath := filepath.Join(tmp, "key.pem")
	if err := runVerb([]string{"keygen", "--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	path := writeTestConfig(t, `
schema = 1
[identity]
key_file = "`+keyPath+`"
[agent]
listen = "127.0.0.1:0"
authorized_clients = ["`+pin+`"]
`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	root := newRootCmd()
	root.SetArgs([]string{"--config", path, "agent"})
	err := root.ExecuteContext(ctx)
	code := exitCode(err)
	if code == 2 {
		t.Errorf("agent with valid config should not fail at resolution (exit 2): %v", err)
	}
}

// TestAgentReverseMode verifies that an agent configured with dial= (reverse
// mode) gives the "not yet supported; later phase" message and exit 2.
func TestAgentReverseMode(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[agent]
dial = "remote.example.com:7443"
authorized_clients = ["`+pin+`"]
`)
	err := runVerb([]string{"--config", path, "agent"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for reverse-mode agent, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "later phase") {
		t.Errorf("error should mention 'later phase', got: %v", err)
	}
}

// ---- bindFreePort stability -------------------------------------------------

// TestBindFreePortStable verifies that bindFreePort returns the same port when
// called twice on the same base (nothing is holding it between calls).
func TestBindFreePortStable(t *testing.T) {
	port1, err := bindFreePort("127.0.0.1", 41000, 10)
	if err != nil {
		t.Fatalf("bindFreePort call 1: %v", err)
	}
	port2, err := bindFreePort("127.0.0.1", 41000, 10)
	if err != nil {
		t.Fatalf("bindFreePort call 2: %v", err)
	}
	if port1 != port2 {
		t.Errorf("bindFreePort returned different ports: %d vs %d", port1, port2)
	}
}
