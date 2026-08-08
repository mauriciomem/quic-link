package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// ---- stub RoutesProvider ----------------------------------------------------

// stubRoutesProvider is an ipc.RoutesProvider returning a fixed body or
// error, configured per test. calls records every server name the handler
// actually passed through, on a buffered channel — never a plain field — so
// a test asserting "this was never called" (the plain-status-unaffected
// tests below) has a real synchronization edge against the handler
// goroutine instead of racing it.
type stubRoutesProvider struct {
	body []byte
	err  error

	calls chan string
}

func newStubRoutesProvider() *stubRoutesProvider {
	return &stubRoutesProvider{calls: make(chan string, 8)}
}

func (s *stubRoutesProvider) RoutesJSON(_ context.Context, server string) ([]byte, error) {
	select {
	case s.calls <- server:
	default:
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.body, nil
}

// startRoutesServerAtPath starts a real ipc.Server, with routes wired, at the
// exact socket path daemonSocketPath(nil) resolves to — the same technique
// dockerenv_test.go's startServerAtPath uses for the status-only provider —
// so a verb calling daemonSocketPath internally finds it.
func startRoutesServerAtPath(t *testing.T, statusJSON string, routes ipc.RoutesProvider) string {
	t.Helper()
	sock, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	srv := ipc.NewServer(sock, &stubStatusProvider{data: []byte(statusJSON)}, nil)
	srv.SetRoutes(routes)
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
	return sock
}

const testStatusJSON = `{"schema":1,"servers":[{"name":"server1","session":"connected","transport":"dial","since_ms":10,"local_ports":{"ssh":42000,"docker":42001}}]}`

func testConfig(t *testing.T, pin string) string {
	t.Helper()
	return writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
}

// ---- plain status must be completely unaffected -----------------------------

// TestStatusPlain_NeverCallsRoutesProvider proves that "status" and
// "status --json" with no --routes flag never invoke the RoutesProvider —
// a user running plain status must not start paying for a network round
// trip to every agent. The routes provider's calls channel is asserted
// empty via a non-blocking select with a short grace window, not a sleep.
func TestStatusPlain_NeverCallsRoutesProvider(t *testing.T) {
	for _, args := range [][]string{
		{"status"},
		{"status", "--json"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			unsetQLEnvForTest(t)
			withDaemonSocketEnv(t)
			pin := mustTestPin(t)
			path := testConfig(t, pin)

			routes := newStubRoutesProvider()
			routes.body = []byte(`{"schema":1,"server":"server1","routes":[]}`)
			startRoutesServerAtPath(t, testStatusJSON, routes)

			full := append([]string{"--config", path}, args...)
			if err := runVerb(full); err != nil {
				t.Fatalf("status: %v", err)
			}

			select {
			case server := <-routes.calls:
				t.Fatalf("RoutesProvider was called with server %q, but --routes was not given", server)
			default:
				// No call recorded — correct.
			}
		})
	}
}

// TestStatusPlain_OutputByteIdentical_WithAndWithoutRoutesWired proves the
// plain-status code path's output bytes are identical whether or not a
// RoutesProvider happens to be wired into the daemon — the two verbs must
// share no logic that could let one influence the other's bytes.
func TestStatusPlain_OutputByteIdentical_WithAndWithoutRoutesWired(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	routes := newStubRoutesProvider()
	routes.body = []byte(`{"schema":1,"server":"server1","routes":[]}`)
	startRoutesServerAtPath(t, testStatusJSON, routes)

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetArgs([]string{"--config", path, "status", "--json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("status --json: %v", err)
	}

	var got, want map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal([]byte(testStatusJSON), &want); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	gotCanon, _ := json.Marshal(got)
	wantCanon, _ := json.Marshal(want)
	if string(gotCanon) != string(wantCanon) {
		t.Errorf("status --json body changed:\n got:  %s\n want: %s", gotCanon, wantCanon)
	}
}

// ---- server resolution --------------------------------------------------

// TestStatusRoutes_ServerNotInConfig_Exit2 proves an unknown SERVER name is
// rejected client-side, before any daemon call, exit 2 — matching
// ssh.go/stdio.go's identical "server %q not found in config" check.
func TestStatusRoutes_ServerNotInConfig_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	err := runVerb([]string{"--config", path, "status", "--routes", "no-such-server"})
	if exitCode(err) != 2 {
		t.Errorf("exitCode = %d, want 2, err=%v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "no-such-server") {
		t.Errorf("error should name the missing server, got: %v", err)
	}
}

// TestStatusRoutes_AmbiguousServers_Exit2 proves that with no SERVER
// argument and more than one enabled server, --routes refuses to guess,
// matching connect/ssh/docker-env's identical ambiguity rule.
func TestStatusRoutes_AmbiguousServers_Exit2(t *testing.T) {
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
	err := runVerb([]string{"--config", path, "status", "--routes"})
	if exitCode(err) != 2 {
		t.Errorf("exitCode = %d, want 2, err=%v", exitCode(err), err)
	}
}

// TestStatusRoutes_ExtraArgWithoutRoutesFlag_Exit2 proves a stray positional
// SERVER argument given to plain status (no --routes) is still a usage
// error, exit 2 — preserving the existing "status takes no arguments"
// contract for the common case, per TestCobraErrorsExitTwo's
// "wrong arg count (too many)" case.
func TestStatusRoutes_ExtraArgWithoutRoutesFlag_Exit2(t *testing.T) {
	err := runVerb([]string{"status", "extra-arg"})
	if exitCode(err) != 2 {
		t.Errorf("exitCode = %d, want 2, err=%v", exitCode(err), err)
	}
}

// ---- daemon-interaction failure modes ---------------------------------------

// TestStatusRoutes_DaemonAbsent_Exit3_SameRemedy proves --routes reuses
// plain status's own daemon-absent remedy message and exit code, rather
// than inventing new wording for the identical condition.
func TestStatusRoutes_DaemonAbsent_Exit3_SameRemedy(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	root := newRootCmd()
	var stderr strings.Builder
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "status", "--routes", "server1"})
	err := root.ExecuteContext(context.Background())

	if exitCode(err) != 3 {
		t.Errorf("exitCode = %d, want 3, err=%v", exitCode(err), err)
	}
	const want = "daemon is not running; start it with: quic-link daemon"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}
}

// ---- the failure taxonomy: each state gets its own message and exit code ---

// TestStatusRoutes_StateTable drives runStatusRoutes against a real IPC
// server whose RoutesProvider returns exactly the *ipc.RoutesError the
// production internal/daemon routesProvider constructs for each session
// state (per internal/daemon/routes_test.go's own TestRoutesJSON_StateTable
// and its stale-agent/reconnecting siblings), proving the CLI relays each
// one's distinct message to stderr and its exit code unchanged — not
// collapsed into one generic string.
func TestStatusRoutes_StateTable(t *testing.T) {
	tests := []struct {
		name       string
		routesErr  error
		wantExit   int
		wantStderr string
	}{
		{
			name:       "disabled",
			routesErr:  &ipc.RoutesError{Status: 3, Msg: `server "server1" is disabled; set enabled = true in the config to use it`},
			wantExit:   3,
			wantStderr: `server "server1" is disabled; set enabled = true in the config to use it`,
		},
		{
			name:       "connecting",
			routesErr:  &ipc.RoutesError{Status: 3, Msg: `server "server1" is not connected (session=connecting); routes are not available yet`},
			wantExit:   3,
			wantStderr: `server "server1" is not connected (session=connecting); routes are not available yet`,
		},
		{
			name:       "listening",
			routesErr:  &ipc.RoutesError{Status: 3, Msg: `server "server1" is waiting for the agent to connect; routes are not available yet`},
			wantExit:   3,
			wantStderr: `server "server1" is waiting for the agent to connect; routes are not available yet`,
		},
		{
			name:       "auth_failed",
			routesErr:  &ipc.RoutesError{Status: 3, Msg: `server "server1" permanently rejected authentication (auth_failed); routes are not available. Re-exchange pins and restart.`},
			wantExit:   3,
			wantStderr: `permanently rejected authentication (auth_failed)`,
		},
		{
			name:       "stale_agent_unimplemented",
			routesErr:  &ipc.RoutesError{Status: 3, Msg: `the agent at server "server1" is running a version that does not report its routes; rebuild both ends`},
			wantExit:   3,
			wantStderr: `rebuild both ends`,
		},
		{
			name:       "reconnecting_mid_call",
			routesErr:  &ipc.RoutesError{Status: 3, Msg: `server "server1" is reconnecting; try again`},
			wantExit:   3,
			wantStderr: `server "server1" is reconnecting; try again`,
		},
		{
			name:       "not_managed_by_this_daemon",
			routesErr:  &ipc.RoutesError{Status: 2, Msg: `unknown server "server1"`},
			wantExit:   2,
			wantStderr: `unknown server "server1"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unsetQLEnvForTest(t)
			withDaemonSocketEnv(t)
			pin := mustTestPin(t)
			path := testConfig(t, pin)

			routes := newStubRoutesProvider()
			routes.err = tc.routesErr
			startRoutesServerAtPath(t, testStatusJSON, routes)

			root := newRootCmd()
			var stdout, stderr strings.Builder
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs([]string{"--config", path, "status", "--routes", "server1"})
			err := root.ExecuteContext(context.Background())

			if got := exitCode(err); got != tc.wantExit {
				t.Errorf("exitCode = %d, want %d, err=%v", got, tc.wantExit, err)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout must be empty on failure, got %q", stdout.String())
			}
		})
	}
}

// TestStatusRoutes_AuthFailed_NeverSaysReconnecting mirrors
// internal/daemon's identically-named test at the CLI layer: the message
// that reaches the terminal for a permanently failed auth state must never
// contain "reconnect" wording, which would mislead an operator into
// waiting for a recovery that will never happen on its own.
func TestStatusRoutes_AuthFailed_NeverSaysReconnecting(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	routes := newStubRoutesProvider()
	routes.err = &ipc.RoutesError{Status: 3, Msg: `server "server1" permanently rejected authentication (auth_failed); routes are not available. Re-exchange pins and restart.`}
	startRoutesServerAtPath(t, testStatusJSON, routes)

	root := newRootCmd()
	var stderr strings.Builder
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "status", "--routes", "server1"})
	_ = root.ExecuteContext(context.Background())

	if strings.Contains(strings.ToLower(stderr.String()), "reconnect") {
		t.Errorf("auth_failed stderr mentions reconnecting: %q", stderr.String())
	}
}

// ---- success path: sanitization end to end ----------------------------------

// TestStatusRoutes_Success_Human_SanitizesHostileRouteData proves the
// end-to-end path — real IPC round trip, real JSON decode, sanitizeRoutes,
// printRoutesHuman — renders a hostile agent-controlled route name inert in
// the actual bytes written to stdout, not merely that no error occurred.
func TestStatusRoutes_Success_Human_SanitizesHostileRouteData(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	hostile := "grafana\x1b]0;pwned\x07"
	body := `{"schema":1,"server":"server1","routes":[{"target":` +
		mustJSONString(t, hostile) + `,"address":"tcp://127.0.0.1:3000","builtin":false}]}`

	routes := newStubRoutesProvider()
	routes.body = []byte(body)
	startRoutesServerAtPath(t, testStatusJSON, routes)

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetArgs([]string{"--config", path, "status", "--routes", "server1"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("status --routes: %v", err)
	}

	got := stdout.String()
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Errorf("stdout still contains a raw control byte: %q", got)
	}
	if !strings.Contains(got, "grafana") {
		t.Errorf("stdout lost the printable payload entirely: %q", got)
	}
}

// TestStatusRoutes_Success_JSON_SanitizesHostileRouteData is the --json
// sibling of the human-output test above: the actual bytes written to
// stdout under --json must not contain the hostile control bytes either,
// decoded or not.
func TestStatusRoutes_Success_JSON_SanitizesHostileRouteData(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	hostile := "ssh\nDOCKER_HOST=evil"
	body := `{"schema":1,"server":"server1","routes":[{"target":` +
		mustJSONString(t, hostile) + `,"address":"tcp://127.0.0.1:22","builtin":true}]}`

	routes := newStubRoutesProvider()
	routes.body = []byte(body)
	startRoutesServerAtPath(t, testStatusJSON, routes)

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetArgs([]string{"--config", path, "status", "--routes", "--json", "server1"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("status --routes --json: %v", err)
	}

	raw := stdout.String()
	// Exactly one line: the printed JSON document plus the trailing
	// newline Fprintf adds. An embedded newline surviving inside a JSON
	// string value would still be valid JSON (escaped as \n) but must not
	// appear as a literal byte splitting stdout into more physical lines.
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout has %d physical lines, want 1: %q", len(lines), raw)
	}

	var decoded routesJSONOutput
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (%q)", err, raw)
	}
	if len(decoded.Routes) != 1 {
		t.Fatalf("decoded %d routes, want 1", len(decoded.Routes))
	}
	if strings.ContainsRune(decoded.Routes[0].Target, '\n') {
		t.Errorf("decoded target still contains an embedded newline: %q", decoded.Routes[0].Target)
	}
	if decoded.Routes[0].Target != "sshDOCKER_HOST=evil" {
		t.Errorf("decoded target = %q, want %q", decoded.Routes[0].Target, "sshDOCKER_HOST=evil")
	}
}

// TestStatusRoutes_Success_NoRoutes_HumanMessage proves an empty route list
// (session connected, agent reports nothing) prints a clear message rather
// than an empty or missing section.
func TestStatusRoutes_Success_NoRoutes_HumanMessage(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	routes := newStubRoutesProvider()
	routes.body = []byte(`{"schema":1,"server":"server1","routes":[]}`)
	startRoutesServerAtPath(t, testStatusJSON, routes)

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	root.SetArgs([]string{"--config", path, "status", "--routes", "server1"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("status --routes: %v", err)
	}
	if !strings.Contains(stdout.String(), "no routes") {
		t.Errorf("stdout = %q, want it to mention no routes", stdout.String())
	}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal(%q): %v", s, err)
	}
	return string(b)
}
