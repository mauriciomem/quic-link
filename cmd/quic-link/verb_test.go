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

// unsetQLEnvForTest removes the environment variables that name settings, so
// prior env state does not bleed into a test.
//
// It deliberately does not touch the home directory, which is the other way this
// machine's own configuration reaches a test: doing that needs t.Setenv, which
// cannot be used by a parallel test. Tests that must see no configuration at all
// call detachHomeForTest as well.
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

// detachHomeForTest points the home directory at an empty temporary one, so a
// test reads no settings and no key belonging to whoever is running it.
//
// This is separate from the variable-clearing above because it cannot be done
// for every caller: it uses t.Setenv, which the testing package forbids in a
// parallel test, and some tests here are parallel. Those that depend on there
// being no configuration call this as well.
//
// It matters more than it looks. Settings and the default identity are both
// found under the invoking user's home, so a test asking for behaviour with
// neither would silently use the developer's own and report the state of their
// machine. Two separate groups of tests here were doing exactly that: one
// expected a complaint about missing authorized clients and instead found a
// working agent, and four others found a real identity key where they had
// created none.
//
// The replacement is a temporary directory rather than an empty value, because
// asking for the home directory when there is none is itself an error on some
// platforms, and the test would then exercise that instead of its subject.
func detachHomeForTest(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
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
	cancel() // cancel immediately so the daemon owner's dial attempt returns quickly
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
	// Exit 3: the name resolved and the server is switched off, which is a state
	// to change rather than a command to correct.
	if exitCode(err) != 3 {
		t.Errorf("expected exit 3 for disabled server, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("error should mention 'disabled', got: %v", err)
	}
}

// Reverse mode is implemented; connect no longer refuses it. What that path
// still owes an operator is covered in reverse_guard_test.go, which checks the
// failures that remain real: an unparseable, taken, or privileged address.

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
	if err == nil || !strings.Contains(err.Error(), "no address to ping") {
		t.Errorf("error should explain there is no address to ping, got: %v", err)
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

// An agent configured to connect out is now supported; see agent_dial_test.go.
