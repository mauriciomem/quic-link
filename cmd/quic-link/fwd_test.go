package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- pure unit tests: arg parsing --------------------------------------------

func TestSplitFwdArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantServer string
		wantTarget string
		wantErr    bool
	}{
		{"target only", []string{"pg"}, "", "pg", false},
		{"server and target", []string{"server1", "pg"}, "server1", "pg", false},
		{"no args", []string{}, "", "", true},
		{"too many args", []string{"a", "b", "c"}, "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotServer, gotTarget, err := splitFwdArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				if exitCode(err) != 2 {
					t.Errorf("exitCode = %d, want 2 (usage error)", exitCode(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotServer != tc.wantServer || gotTarget != tc.wantTarget {
				t.Errorf("got (%q, %q), want (%q, %q)", gotServer, gotTarget, tc.wantServer, tc.wantTarget)
			}
		})
	}
}

// TestParseFwdTarget_LocalPortValidation is the LOCAL_PORT validation table
// from the work item: 0, negative, non-numeric, and >65535 are usage errors
// (exit 2); a valid port and an omitted port both succeed.
func TestParseFwdTarget_LocalPortValidation(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		wantTarget string
		wantPort   int
		wantErr    bool
	}{
		{"omitted suffix: auto-pick", "pg", "pg", 0, false},
		{"valid port", "pg:15432", "pg", 15432, false},
		{"port 1 (minimum valid)", "pg:1", "pg", 1, false},
		{"port 65535 (maximum valid)", "pg:65535", "pg", 65535, false},
		{"zero is rejected, not a synonym for auto-pick", "pg:0", "", 0, true},
		{"negative port", "pg:-5", "", 0, true},
		{"non-numeric port", "pg:abc", "", 0, true},
		{"port above 65535", "pg:65536", "", 0, true},
		{"empty port after colon", "pg:", "", 0, true},

		// TARGET must be a valid route name (internal/router.ValidateRouteName),
		// the same rule the agent enforces — validating it locally means a
		// bad name fails fast with a clear local message instead of a remote
		// bad-header failure.
		{"invalid target name: slash", "pg/app", "", 0, true},
		{"invalid target name: slash, with a port suffix", "pg/app:1234", "", 0, true},
		{"invalid target name: empty", "", "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTarget, gotPort, err := parseFwdTarget(tc.arg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got nil", tc.arg)
				}
				if exitCode(err) != 2 {
					t.Errorf("exitCode = %d, want 2 (usage error) for %q", exitCode(err), tc.arg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.arg, err)
			}
			if gotTarget != tc.wantTarget || gotPort != tc.wantPort {
				t.Errorf("parseFwdTarget(%q) = (%q, %d), want (%q, %d)",
					tc.arg, gotTarget, gotPort, tc.wantTarget, tc.wantPort)
			}
		})
	}
}

// ---- bind error classification -----------------------------------------------

func TestBindFwdListener_PortInUse_Exit2(t *testing.T) {
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer held.Close()
	port := held.Addr().(*net.TCPAddr).Port

	_, _, err = bindFwdListener(port)
	if err == nil {
		t.Fatal("expected an error binding an already-used port")
	}
	if exitCode(err) != 2 {
		t.Errorf("exitCode = %d, want 2", exitCode(err))
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error should name the port as already in use, got: %v", err)
	}
}

// TestBindFwdListener_Privileged_Exit2_NoSudoMention verifies F14/S4: the
// error is classified via errors.Is(err, syscall.EACCES), and the message
// never suggests running quic-link with elevated privilege.
func TestBindFwdListener_Privileged_Exit2_NoSudoMention(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; a privileged-port bind cannot fail with EACCES")
	}
	_, _, err := bindFwdListener(1)
	if err == nil {
		t.Skip("port 1 bound successfully in this environment; cannot exercise EACCES here")
	}
	if exitCode(err) != 2 {
		t.Errorf("exitCode = %d, want 2", exitCode(err))
	}
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), "sudo") {
		t.Errorf("privileged-port message must never mention sudo, got: %q", msg)
	}
	if !strings.Contains(msg, "1024") {
		t.Errorf("privileged-port message should direct the user to a port >= 1024, got: %q", msg)
	}
}

func TestClassifyBindError_UsesErrnoNotString(t *testing.T) {
	// A plain syscall.EADDRINUSE (not wrapped in any particular string form)
	// must classify correctly via errors.Is, proving the check is not a
	// string match on Error().
	err := classifyBindError(5432, syscall.EADDRINUSE)
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("expected an in-use message, got: %v", err)
	}
	err = classifyBindError(80, syscall.EACCES)
	if strings.Contains(strings.ToLower(err.Error()), "sudo") {
		t.Errorf("privileged message must not mention sudo, got: %v", err)
	}
}

// ---- concurrency-safe output buffer -------------------------------------------

// syncBuilder is a strings.Builder safe for concurrent Write from the
// cobra command's own goroutine and concurrent Len/String reads from a test
// goroutine polling for the CONTRACT line while fwd's Run blocks in the
// foreground. Plain strings.Builder is not safe for that pattern (proven by
// -race here) since fwd, unlike every other verb tested in this file, keeps
// writing (implicitly, by staying alive) after RunE prints the CONTRACT line
// and while the test polls for it.
type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuilder) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

// ---- preflight integration through a real IPC server + in-memory agent -----
//
// withDaemonSocketEnv (dockerenv_test.go, same package) points the daemon
// socket resolution at a fresh temp XDG_RUNTIME_DIR; reused here as-is.

// startFwdAxServer starts a real ipc.Server backed by pool AT the exact
// socket path fwd's own daemonSocketPath(nil) resolution will look for
// (rather than startAxTestServer's ad hoc /tmp path, which fwd would never
// find), mirroring dockerenv_test.go's startServerAtPath but for an
// attach-capable pool instead of a status-only stub.
func startFwdAxServer(t *testing.T, pool ipc.AttachPool) string {
	t.Helper()
	sock, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	srv := ipc.NewServerWithOpts(sock, &axStatusStub{}, pool, ipc.ServerOpts{UID: os.Getuid()})
	if err := srv.Listen(); err != nil {
		t.Fatalf("startFwdAxServer listen: %v", err)
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

// TestFwd_UnknownTarget_PreflightExit5_NothingBound is the startup-preflight
// contract test: an unknown target must exit 5 before any local port is ever
// bound and before the CONTRACT line is ever printed.
func TestFwd_UnknownTarget_PreflightExit5_NothingBound(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	agentConn := axBuildMemAgent(t)
	pool := &axConnPool{conn: agentConn}
	startFwdAxServer(t, pool)

	root := newRootCmd()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "fwd", "server1", "no-such-route"})
	err := root.ExecuteContext(context.Background())

	if err == nil {
		t.Fatal("expected an error for an unknown target")
	}
	if got := exitCode(err); got != 5 {
		t.Errorf("exitCode = %d, want 5 (unknown target)", got)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty (nothing was ever bound, no CONTRACT line), got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "no target") {
		t.Errorf("stderr should contain the agent's verbatim message, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "route") {
		t.Errorf("stderr should contain 'add a route' guidance, got %q", stderr.String())
	}
}

// TestFwd_DaemonAbsent_Exit3 verifies fwd's own no-fallback rule: with no
// daemon running at all, fwd exits 3 with a remedy naming quic-link daemon,
// and nothing is ever bound.
func TestFwd_DaemonAbsent_Exit3(t *testing.T) {
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
	root.SetArgs([]string{"--config", path, "fwd", "server1", "pg"})
	err := root.ExecuteContext(context.Background())

	if err == nil {
		t.Fatal("expected an error when no daemon is running")
	}
	if got := exitCode(err); got != 3 {
		t.Errorf("exitCode = %d, want 3 (daemon absent)", got)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "quic-link daemon") {
		t.Errorf("stderr should name the remedy 'quic-link daemon', got %q", stderr.String())
	}
}

// TestFwd_DaemonAbsent_ErrorMessageNotMisleading verifies that fwd's
// daemon-absent error does not borrow errFinalExitCode's hardcoded "attach
// refused" wording: no attach was ever attempted, since no daemon was ever
// reached, so nothing was refused. This is the same defect class already
// fixed once for ssh's own child-process exit code (errExecExitCode).
func TestFwd_DaemonAbsent_ErrorMessageNotMisleading(t *testing.T) {
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
	root.SetArgs([]string{"--config", path, "fwd", "server1", "pg"})
	err := root.ExecuteContext(context.Background())

	if err == nil {
		t.Fatal("expected an error when no daemon is running")
	}
	if strings.Contains(err.Error(), "attach refused") {
		t.Errorf("daemon-absent error must not claim anything was refused (nothing was ever reached), got: %v", err)
	}
}

// TestFwd_NotReady_WarnsAndBindsAndListens verifies the deliberately
// asymmetric preflight rule: a daemon-scoped, transient failure (status 3)
// does NOT fail startup — it warns on stderr and still binds and listens.
func TestFwd_NotReady_WarnsAndBindsAndListens(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	pool := &axNotReadyPool{}
	startFwdAxServer(t, pool)

	ctx, cancel := context.WithCancel(context.Background())
	root := newRootCmd()
	var stdout, stderr syncBuilder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "fwd", "server1", "pg"})

	errCh := make(chan error, 1)
	go func() { errCh <- root.ExecuteContext(ctx) }()

	// Wait for the CONTRACT line to appear on stdout — proof that fwd bound
	// the port and started listening despite the not-ready warning.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && stdout.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if stdout.Len() == 0 {
		cancel()
		t.Fatal("fwd never printed the CONTRACT line; it should bind and listen despite a not-ready session")
	}
	if !strings.Contains(stdout.String(), "listening 127.0.0.1:") {
		t.Errorf("stdout = %q, want a CONTRACT line", stdout.String())
	}
	if !strings.Contains(stderr.String(), "warning") {
		t.Errorf("stderr should contain a warning for the not-ready session, got %q", stderr.String())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected a clean exit after Ctrl-C, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fwd did not exit after cancellation")
	}
}

// TestFwd_ValidTarget_ContractLine_ByteExact is the end-to-end happy path
// through a real IPC server and a real (in-memory) QUIC agent: the CONTRACT
// line is printed exactly, and a connection through the printed port carries
// a byte-exact round trip to the agent's echo target.
func TestFwd_ValidTarget_ContractLine_ByteExact(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	agentConn := axBuildMemAgent(t)
	pool := &axConnPool{conn: agentConn}
	startFwdAxServer(t, pool)

	ctx, cancel := context.WithCancel(context.Background())
	root := newRootCmd()
	var stdout, stderr syncBuilder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "fwd", "server1", "ssh"})

	errCh := make(chan error, 1)
	go func() { errCh <- root.ExecuteContext(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && stdout.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	line := stdout.String()
	if line == "" {
		cancel()
		t.Fatal("fwd never printed the CONTRACT line")
	}
	if !strings.HasPrefix(line, "listening 127.0.0.1:") || !strings.HasSuffix(line, " -> server1:ssh\n") {
		t.Fatalf("CONTRACT line = %q, want the exact 'listening 127.0.0.1:<port> -> server1:ssh' shape", line)
	}

	// Extract the bound port and dial it directly.
	portStr := strings.TrimPrefix(line, "listening 127.0.0.1:")
	portStr = strings.TrimSuffix(portStr, " -> server1:ssh\n")
	conn, err := net.Dial("tcp4", "127.0.0.1:"+portStr)
	if err != nil {
		cancel()
		t.Fatalf("dial the printed port: %v", err)
	}
	payload := []byte("fwd-cmd-level-round-trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}
	conn.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected a clean exit after Ctrl-C, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fwd did not exit after cancellation")
	}
}

// TestFwd_UnauthorizedAtPreflight_Exit4 runs a real agent whose policy denies
// every target, proving fwd's preflight surfaces a genuine agent-scoped
// authorization refusal (status 4) as exit 4, distinctly from the daemon-
// scoped status-3 case above.
func TestFwd_UnauthorizedAtPreflight_Exit4(t *testing.T) {
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	agentConn := fwdBuildDenyAllMemAgent(t)
	pool := &axConnPool{conn: agentConn}
	startFwdAxServer(t, pool)

	root := newRootCmd()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", path, "fwd", "server1", "ssh"})
	err := root.ExecuteContext(context.Background())

	if got := exitCode(err); got != 4 {
		t.Errorf("exitCode = %d, want 4 (unauthorized), err=%v, stderr=%q", got, err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty, got %q", stdout.String())
	}
}

// fwdBuildDenyAllMemAgent starts an in-memory QUIC agent, identical in shape
// to attach_exit_test.go's axBuildMemAgent, except its router policy denies
// every target — used to exercise a genuine agent-scoped authorization
// refusal end to end.
func fwdBuildDenyAllMemAgent(t *testing.T) tunnel.StreamConn {
	t.Helper()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("fwdBuildDenyAllMemAgent: NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("fwdBuildDenyAllMemAgent: NewIdentity (server): %v", err)
	}

	hub := mem.NewHub()
	const srvAddr = "fwd-deny-agent:42"
	srvT := hub.Transport(srvAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("fwd-deny-client:42", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("fwdBuildDenyAllMemAgent: srvT.Listen: %v", err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fwdBuildDenyAllMemAgent: echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go axRunEchoServer(echoLn)

	denyAll := router.PolicyFunc(func(router.Identity, proto.Header) error {
		return errors.New("denied by test policy")
	})
	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, denyAll)
	if err != nil {
		t.Fatalf("fwdBuildDenyAllMemAgent: router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	conn, err := cliT.Dial(ctx, srvAddr)
	if err != nil {
		t.Fatalf("fwdBuildDenyAllMemAgent: Dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "fwd-deny-test done") }) //nolint:errcheck

	cclient, cerr := tunnel.OpenControl(ctx, conn, "fwd-deny-test", control.OpenOpts{})
	if cerr != nil {
		t.Logf("fwdBuildDenyAllMemAgent: OpenControl: %v (acceptable for short test)", cerr)
	} else if cclient != nil {
		t.Cleanup(func() { cclient.Close() })
	}

	return conn
}
