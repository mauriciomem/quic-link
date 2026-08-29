package main

// @spec-handoff
//
// TestPing_DaemonManagedServer_NotInSettings_ExplainsWhyNotJustNotFound pins
// this: ping cannot fall back to the running daemon the way most other verbs
// do (pingRun dials its own fresh QUIC connection per probe, so it needs a
// direct address and pin, and the daemon's status snapshot carries
// neither), but the message for a server that IS daemon-managed and simply
// absent from settings must say so — not claim the server is "not found"
// anywhere, which sends the reader to edit a file that will not fix
// anything and never mentions the --server/--pin escape hatch that already
// exists.
//
// Interface: ping's existing "server %q not found in config" branch
// (ping.go, the len(args)==1 miss path). Exit code is unchanged at 2
// (usage) in both cases below — this is a message-only fix, not a
// resolution-path change.
//
// Behaviors covered:
//   - a name the (faked, real-socket) daemon reports as managed, but that
//     is absent from a.cfg.Servers: the message names the daemon, explains
//     that ping needs an address+pin the daemon does not expose over
//     status, and points at the [servers.<name>] remedy or --server/--pin;
//     exit code stays 2.
//   - a name in neither the daemon's snapshot nor settings: the existing
//     "not found in config" message is preserved unchanged; exit code 2.
//
// Edge cases: no daemon running at all (existing TestPingReverseServer etc.
// already cover the pure-settings path and are left untouched).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// TestPing_DaemonManagedServer_NotInSettings_ExplainsWhyNotJustNotFound is
// the empirical regression from the audit's run B: a daemon started
// with `--server-add web=HOST:PORT --server-pin web=PIN` and zero settings
// file entries manages "web" entirely in its own memory. Before the fix,
// `ping web` said "not found in config" — the published quickstart's own
// example (docs/getting-started.md) hitting exactly this and reading like
// the server does not exist anywhere, when the daemon is actively managing
// it right under that name.
func TestPing_DaemonManagedServer_NotInSettings_ExplainsWhyNotJustNotFound(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	// A settings file that defines no servers at all: "web" exists only in
	// the daemon's own memory, the exact shape the audit's empirical run B
	// used.
	path := writeTestConfig(t, "schema = 1\n")

	sockPath, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	statusJSON := `{"schema":1,"servers":[{"name":"web","session":"connected","transport":"dial","since_ms":10,"local_ports":{"ssh":0,"docker":0}}]}`
	startServerAtPath(t, sockPath, statusJSON)

	root := newRootCmd()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "ping", "web"})
	err = root.ExecuteContext(context.Background())

	if exitCode(err) != 2 {
		t.Fatalf("exitCode = %d, want 2 (usage — the diagnosis changes, not the exit code), err=%v", exitCode(err), err)
	}
	if err == nil {
		t.Fatal("expected an error for a server ping cannot probe directly")
	}
	msg := err.Error()
	if strings.Contains(msg, "not found in config") {
		t.Errorf("message must not claim the server is not found anywhere; the daemon manages it: %q", msg)
	}
	if !strings.Contains(msg, "daemon") {
		t.Errorf("message should say the server is managed by the running daemon, got: %q", msg)
	}
	if !strings.Contains(msg, "--server") || !strings.Contains(msg, "--pin") {
		t.Errorf("message should point at the --server/--pin escape hatch, got: %q", msg)
	}
}

// TestPing_TrulyUnknownServer_KeepsExistingMessage pins the other half of
// the fix: a name in neither the daemon's snapshot nor settings keeps the
// original "not found in config" wording — the branch introduced for the
// daemon-managed case must not fire for a genuinely nonexistent name.
func TestPing_TrulyUnknownServer_KeepsExistingMessage(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	path := writeTestConfig(t, "schema = 1\n")

	sockPath, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	statusJSON := `{"schema":1,"servers":[{"name":"web","session":"connected","transport":"dial","since_ms":10,"local_ports":{"ssh":0,"docker":0}}]}`
	startServerAtPath(t, sockPath, statusJSON)

	err = runVerb([]string{"--config", path, "ping", "nosuchserver"})
	if exitCode(err) != 2 {
		t.Fatalf("exitCode = %d, want 2, err=%v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "not found in config") {
		t.Errorf("a truly unknown name should keep the existing message, got: %v", err)
	}
}

// TestAggregateProbeError verifies that aggregateProbeError returns the right
// sentinel (or none) depending on which accumulated errors are present, and
// that auth failure takes precedence over unreachability.
func TestAggregateProbeError(t *testing.T) {
	authErr := transport.ErrAuthFailed
	unreachErr := transport.ErrUnreachable

	cases := []struct {
		name       string
		authErr    error
		unreachErr error
		wantAuth   bool // result must wrap ErrAuthFailed
		wantUnrch  bool // result must wrap ErrUnreachable
	}{
		{
			name:     "auth only -> exits 4",
			authErr:  authErr,
			wantAuth: true,
		},
		{
			name:       "unreachable only -> exits 3",
			unreachErr: unreachErr,
			wantUnrch:  true,
		},
		{
			name:       "both -> auth takes precedence (exits 4)",
			authErr:    authErr,
			unreachErr: unreachErr,
			wantAuth:   true,
		},
		{
			name: "neither -> generic (exits 1)",
			// both nil: result must not carry either sentinel
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := aggregateProbeError(3, tc.authErr, tc.unreachErr)
			if err == nil {
				t.Fatal("aggregateProbeError returned nil; always expect a non-nil error when all probes fail")
			}
			gotAuth := errors.Is(err, transport.ErrAuthFailed)
			gotUnrch := errors.Is(err, transport.ErrUnreachable)

			if gotAuth != tc.wantAuth {
				t.Errorf("ErrAuthFailed: got %v, want %v (err=%v)", gotAuth, tc.wantAuth, err)
			}
			if gotUnrch != tc.wantUnrch {
				t.Errorf("ErrUnreachable: got %v, want %v (err=%v)", gotUnrch, tc.wantUnrch, err)
			}
		})
	}
}
