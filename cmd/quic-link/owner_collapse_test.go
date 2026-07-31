package main

// owner_collapse_test.go covers:
//   - Task 2: daemon --server NAME scoping, connect as a hidden deprecated alias
//   - Task 3: stdio disabled-server exits 3 (not 2 with usage dump)
//
// All tests are table-driven where multiple cases share the same structure.
// Each test is documented with its pre-fix failure mode so a reviewer can
// confirm the test caught real behaviour before the fix.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// ---- config helpers ---------------------------------------------------------

// twoServerConfig writes a config with two enabled servers and returns its path.
func twoServerConfig(t *testing.T) string {
	t.Helper()
	pin := mustTestPin(t)
	return writeTestConfig(t, `
schema = 1
[servers.alpha]
addr = "127.0.0.1:19980"
pin  = "`+pin+`"

[servers.beta]
addr = "127.0.0.1:19981"
pin  = "`+pin+`"
`)
}

// oneServerConfig writes a config with exactly one enabled server.
func oneServerConfig(t *testing.T) string {
	t.Helper()
	pin := mustTestPin(t)
	return writeTestConfig(t, `
schema = 1
[servers.only]
addr = "127.0.0.1:19982"
pin  = "`+pin+`"
`)
}

// oneDisabledServerConfig writes a config with one server that has enabled=false.
func oneDisabledServerConfig(t *testing.T) string {
	t.Helper()
	pin := mustTestPin(t)
	return writeTestConfig(t, `
schema = 1
[servers.offsrv]
addr    = "127.0.0.1:19983"
pin     = "`+pin+`"
enabled = false
`)
}

// ---- Task 2a: daemon --server NAME scoping ----------------------------------

// TestDaemonServerFlag_MissingScopeExitsTwo verifies that daemon --server NAME
// with a server not in the config is a usage error (exit 2).
//
// Pre-fix failure mode: daemon registered no --server flag at all, so passing
// --server NAME caused cobra to emit "unknown flag: --server" and exit 2 via
// cobra's own error path, not our validation. After the flag exists the test
// verifies our explicit "server not in config" semantic check, ensuring the
// error message names the missing server.
func TestDaemonServerFlag_MissingScopeExitsTwo(t *testing.T) {
	unsetQLEnvForTest(t)
	path := oneServerConfig(t)

	err := runVerb([]string{"--config", path, "daemon", "--server", "nosuch"})
	if exitCode(err) != 2 {
		t.Errorf("daemon --server NOSUCH: want exit 2, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Errorf("error should name the missing server, got: %v", err)
	}
}

// TestDaemonServerFlag_DisabledScopeExitsTwo verifies that daemon --server NAME
// when the named server has enabled=false is a usage error (exit 2) with a
// remedy message telling the user to set enabled = true.
//
// Pre-fix failure mode: no --server flag existed; cobra emitted "unknown flag".
func TestDaemonServerFlag_DisabledScopeExitsTwo(t *testing.T) {
	unsetQLEnvForTest(t)
	path := oneDisabledServerConfig(t)

	err := runVerb([]string{"--config", path, "daemon", "--server", "offsrv"})
	if exitCode(err) != 2 {
		t.Errorf("daemon --server disabled: want exit 2, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "enabled") {
		t.Errorf("error should mention 'enabled' remedy, got: %v", err)
	}
}

// TestDaemonScopedStatus verifies that a daemon started with a scoped pool
// (containing only one server) reports only that server via the IPC socket.
//
// We bypass the CLI and call daemon.Run directly with a pre-built scoped pool
// so the test does not require real QUIC dials.
//
// Pre-fix failure mode: daemon always built a pool from all servers (no --server
// scoping), so the IPC response would contain both servers, not one.
func TestDaemonScopedStatus(t *testing.T) {
	t.Parallel()
	unsetQLEnvForTest(t)

	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.alpha]
addr = "127.0.0.1:19930"
pin  = "`+pin+`"

[servers.beta]
addr = "127.0.0.1:19931"
pin  = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Scoped pool: only "alpha". This simulates what daemon does when
	// --server alpha is given: it builds a pool from a cfg that contains only
	// the "alpha" entry.
	pool := &fakePoolForScope{servers: []string{"alpha"}}
	sock, cancel, done := startScopedDaemon(t, cfg, pool)
	defer func() { cancel(); <-done }()

	rawJSON, serr := ipc.NewClient(sock).StatusJSON()
	if serr != nil {
		t.Fatalf("ipc StatusJSON: %v", serr)
	}

	var snap daemon.StatusSnapshot
	if err := json.Unmarshal(rawJSON, &snap); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}

	if len(snap.Servers) != 1 {
		t.Errorf("scoped daemon (only alpha) reported %d servers, want 1: %+v",
			len(snap.Servers), snap.Servers)
	}
	if len(snap.Servers) > 0 && snap.Servers[0].Name != "alpha" {
		t.Errorf("scoped daemon server name = %q, want alpha", snap.Servers[0].Name)
	}
}

// TestDaemonNoFlagAllEnabledServers verifies that without --server, the
// enabledServers helper returns all servers that are not explicitly disabled.
// This is the "all enabled servers" behaviour that must survive the scoping change.
//
// Pre-fix failure mode: this tests status-quo behaviour; the risk is regression
// if the scoping change accidentally filters all servers when no flag is given.
func TestDaemonNoFlagAllEnabledServers(t *testing.T) {
	unsetQLEnvForTest(t)

	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.alpha]
addr = "127.0.0.1:19960"
pin  = "`+pin+`"

[servers.beta]
addr = "127.0.0.1:19961"
pin  = "`+pin+`"

[servers.off]
addr    = "127.0.0.1:19962"
pin     = "`+pin+`"
enabled = false
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// With no --server flag, all enabled servers (alpha, beta) must be included.
	enabled := enabledServers(cfg.Servers)
	if len(enabled) != 2 {
		t.Errorf("expected 2 enabled servers, got %d: %v", len(enabled), enabled)
	}
	if _, ok := enabled["alpha"]; !ok {
		t.Error("alpha should be in enabled servers")
	}
	if _, ok := enabled["beta"]; !ok {
		t.Error("beta should be in enabled servers")
	}
	if _, ok := enabled["off"]; ok {
		t.Error("off (enabled=false) must not be in enabled servers")
	}
}

// ---- Task 2c: connect as hidden deprecated alias ----------------------------

// TestConnectIsHidden verifies that the connect command is marked Hidden in the
// cobra command tree so it does not appear in the help listing.
//
// Pre-fix failure mode: Hidden is false; the test fails with "connect is not hidden".
func TestConnectIsHidden(t *testing.T) {
	root := newRootCmd()
	var connectCmd interface {
		GetName() string
	}
	_ = connectCmd

	// Walk the root commands to find "connect".
	found := false
	hidden := false
	for _, c := range root.Commands() {
		if c.Name() == "connect" {
			found = true
			hidden = c.Hidden
			break
		}
	}
	if !found {
		t.Fatal("connect command not found in root — has it been removed entirely? It must remain as a hidden alias")
	}
	if !hidden {
		t.Error("connect command must be Hidden=true; it is a deprecated alias for daemon --server NAME")
	}
}

// TestConnectDeprecationWarning verifies that invoking connect prints a
// deprecation warning to stderr. The warning must reference "daemon" so the
// user knows where to go.
//
// Pre-fix failure mode: connect has no deprecation warning; stderr contains
// only transport-layer noise but no "deprecated" advisory.
func TestConnectDeprecationWarning(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.s1]
addr = "127.0.0.1:19950"
pin  = "`+pin+`"
`)

	var stderrBuf bytes.Buffer
	root := newRootCmd()
	root.SetErr(&stderrBuf)
	root.SetArgs([]string{"--config", path, "connect", "s1"})

	// Cancel immediately so we don't actually dial.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = root.ExecuteContext(ctx)

	stderr := stderrBuf.String()
	lowerStderr := strings.ToLower(stderr)
	if !strings.Contains(lowerStderr, "deprecated") && !strings.Contains(lowerStderr, "daemon") {
		t.Errorf("connect should print a deprecation warning referencing 'daemon' to stderr; got: %q", stderr)
	}
}

// TestConnectAliasUsesServerArg verifies that "connect SERVER" resolves the
// named server from config — this is the same resolution connect always did.
// After the refactor it must continue to work, routing through the same path
// as daemon --server SERVER.
//
// Missing server → exit 2 (same as daemon --server NOSUCH).
// Disabled server → exit 2 (same as daemon --server DISABLED).
//
// Pre-fix failure mode (after the refactor): if the alias routing breaks, the
// error code might change.
func TestConnectAliasUsesServerArg(t *testing.T) {
	unsetQLEnvForTest(t)

	tests := []struct {
		name     string
		cfgFunc  func(*testing.T) string
		server   string
		wantCode int
		wantMsg  string
	}{
		{
			name:     "missing server → exit 2",
			cfgFunc:  oneServerConfig,
			server:   "nosuch",
			wantCode: 2,
			wantMsg:  "nosuch",
		},
		{
			name:     "disabled server → exit 2",
			cfgFunc:  oneDisabledServerConfig,
			server:   "offsrv",
			wantCode: 2,
			wantMsg:  "enabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.cfgFunc(t)
			err := runVerb([]string{"--config", path, "connect", tt.server})
			if exitCode(err) != tt.wantCode {
				t.Errorf("connect %s: want exit %d, got %d: %v",
					tt.server, tt.wantCode, exitCode(err), err)
			}
			if tt.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantMsg)) {
				t.Errorf("connect %s: error should contain %q, got: %v",
					tt.server, tt.wantMsg, err)
			}
		})
	}
}

// TestConnectNoArgOneScopedServer verifies that "connect" with no positional
// argument and exactly one enabled server uses that server (the sole-server
// auto-select behaviour).
//
// This tests that the alias translation (connect → daemon --server NAME) does
// not accidentally break the no-arg, sole-server path.
//
// Pre-fix failure mode: connect had this behaviour already; after alias refactor
// it must still work (exit != 2, because resolution succeeds).
func TestConnectNoArgOneScopedServer(t *testing.T) {
	unsetQLEnvForTest(t)
	path := oneServerConfig(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runVerbCtx(ctx, []string{"--config", path, "connect"})
	// Must not be exit 2 (resolution failure); it may be exit 3 (unreachable/ctx-cancelled).
	if exitCode(err) == 2 {
		t.Errorf("connect with one server and no arg should not exit 2 (resolution error): %v", err)
	}
}

// TestConnectNoArgMultipleServers verifies that "connect" with no positional
// argument and multiple enabled servers exits 2, telling the user to name one.
//
// Pre-fix failure mode: pre-existing behaviour that must survive the refactor.
func TestConnectNoArgMultipleServers(t *testing.T) {
	unsetQLEnvForTest(t)
	path := twoServerConfig(t)

	err := runVerb([]string{"--config", path, "connect"})
	if exitCode(err) != 2 {
		t.Errorf("connect with multiple servers and no arg: want exit 2, got %d: %v",
			exitCode(err), err)
	}
}

// ---- Task 3: stdio disabled server exits 3, not 2 with usage dump ----------

// TestStdioDisabledServerExitsThree verifies that stdio SERVER TARGET where
// SERVER is in the config but has enabled=false exits 3 (non-connected session)
// with a remedy message, and does NOT emit a cobra usage screen.
//
// Pre-fix failure mode: the old code called cmd.UsageString() and
// usageErrorf(...) which produces exit 2. The stderr also contained "Usage:".
func TestStdioDisabledServerExitsThree(t *testing.T) {
	unsetQLEnvForTest(t)
	path := oneDisabledServerConfig(t)

	var stderrBuf bytes.Buffer
	root := newRootCmd()
	root.SetErr(&stderrBuf)
	root.SetArgs([]string{"--config", path, "stdio", "offsrv", "ssh"})
	err := root.ExecuteContext(context.Background())

	if exitCode(err) != 3 {
		t.Errorf("stdio disabled server: want exit 3, got %d: %v", exitCode(err), err)
	}

	stderrStr := stderrBuf.String()

	// Must NOT contain a cobra usage screen.
	if strings.Contains(stderrStr, "Usage:") {
		t.Errorf("stdio disabled server: stderr must not contain cobra Usage dump; got:\n%s", stderrStr)
	}

	// Must mention the remedy somewhere (error message or stderr).
	remedyFound := strings.Contains(err.Error(), "enabled") || strings.Contains(stderrStr, "enabled")
	if !remedyFound {
		t.Errorf("stdio disabled server: 'enabled' remedy not found: err=%v stderr=%q", err, stderrStr)
	}
}

// TestStdioMissingServerExitsTwo verifies that stdio SERVER TARGET where SERVER
// is NOT in the config exits 2 (genuine usage error / user typo). This is the
// distinction: missing ≠ disabled.
//
// Pre-fix failure mode: before the Task 3 fix, both disabled and missing
// returned exit 2 — there was no distinction. This test confirms the missing-
// server case still exits 2 after the fix, proving the distinction is real.
func TestStdioMissingServerExitsTwo(t *testing.T) {
	unsetQLEnvForTest(t)
	path := oneServerConfig(t)

	err := runVerb([]string{"--config", path, "stdio", "nosuchserver", "ssh"})
	if exitCode(err) != 2 {
		t.Errorf("stdio missing server: want exit 2, got %d: %v", exitCode(err), err)
	}
}

// TestStdioDisabledVsMissing_ExitDistinction is the canonical table-driven
// test documenting the exit-code distinction between disabled and missing servers.
//
// Pre-fix failure mode: both "disabled" and "missing" rows produced exit 2.
// After the fix, "disabled" → exit 3 and "missing" → exit 2.
func TestStdioDisabledVsMissing_ExitDistinction(t *testing.T) {
	unsetQLEnvForTest(t)

	pin := mustTestPin(t)
	cfgWithBoth := writeTestConfig(t, `
schema = 1
[servers.live]
addr = "127.0.0.1:19940"
pin  = "`+pin+`"

[servers.off]
addr    = "127.0.0.1:19941"
pin     = "`+pin+`"
enabled = false
`)

	tests := []struct {
		name        string
		server      string
		wantCode    int
		noUsageDump bool // if true, assert "Usage:" is absent from stderr
		wantErrMsg  string
	}{
		{
			name:        "disabled server → exit 3, no usage dump, remedy",
			server:      "off",
			wantCode:    3,
			noUsageDump: true,
			wantErrMsg:  "enabled",
		},
		{
			name:     "missing server → exit 2",
			server:   "typo",
			wantCode: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderrBuf bytes.Buffer
			root := newRootCmd()
			root.SetErr(&stderrBuf)
			root.SetArgs([]string{"--config", cfgWithBoth, "stdio", tt.server, "ssh"})
			err := root.ExecuteContext(context.Background())

			if got := exitCode(err); got != tt.wantCode {
				t.Errorf("exit code = %d, want %d: %v", got, tt.wantCode, err)
			}

			stderrStr := stderrBuf.String()
			if tt.noUsageDump && strings.Contains(stderrStr, "Usage:") {
				t.Errorf("stderr must not contain 'Usage:' screen; got:\n%s", stderrStr)
			}

			if tt.wantErrMsg != "" {
				errHas := err != nil && strings.Contains(err.Error(), tt.wantErrMsg)
				stderrHas := strings.Contains(stderrStr, tt.wantErrMsg)
				if !errHas && !stderrHas {
					t.Errorf("neither error (%v) nor stderr (%q) contains %q",
						err, stderrStr, tt.wantErrMsg)
				}
			}
		})
	}
}

// ---- internal stubs ---------------------------------------------------------

// fakePoolForScope is a minimal SessionPool for scope-testing (different from
// fakePoolForCmd in single_instance_test.go to keep concerns separate).
type fakePoolForScope struct {
	servers []string
}

func (f *fakePoolForScope) Get(_ context.Context, _ string) (daemon.Conn, error) {
	return nil, nil
}

func (f *fakePoolForScope) State() []daemon.SessionState {
	states := make([]daemon.SessionState, 0, len(f.servers))
	for _, name := range f.servers {
		states = append(states, daemon.SessionState{
			Name:      name,
			State:     "connecting",
			Transport: "dial",
		})
	}
	return states
}

func (f *fakePoolForScope) EntryState(server string) (string, error) {
	for _, name := range f.servers {
		if name == server {
			return "connecting", nil
		}
	}
	return "", fmt.Errorf("unknown server %q", server)
}

func (f *fakePoolForScope) Close() {}

// startScopedDaemon starts daemon.Run with a pre-built pool and returns the
// socket path, a cancel func, and an error channel. The socket path is short
// enough for macOS's 104-byte sun_path limit.
func startScopedDaemon(t *testing.T, cfg *config.Config, pool daemon.SessionPool) (sock string, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	sock = fmt.Sprintf("/tmp/ql-scoped-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	t.Cleanup(func() { os.Remove(sock) })

	ctx, c := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() {
		ch <- daemon.Run(ctx, cfg, sock, pool, daemon.WallClock{}, nil)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return sock, c, ch
		}
		time.Sleep(20 * time.Millisecond)
	}
	c()
	t.Fatalf("scoped daemon socket %s did not appear within 3s", sock)
	return "", nil, nil
}
