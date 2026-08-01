package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestShellQuoteRoundTrips_PathWithSpaces pins the quoting behaviour by
// actually running the quoted string through a real shell and checking the
// original string comes back byte-exact. This is the same failure mode the
// task's VERIFIED FACT names: an unquoted absolute path containing spaces
// fails with "/bin/bash: line 1: ...: No such file or directory"; the
// quoted form must survive intact through sh -c.
func TestShellQuoteRoundTrips_PathWithSpaces(t *testing.T) {
	cases := []string{
		"/tmp/opencode/dir with spaces/quic-link",
		"/tmp/it's got a quote",
		"plain-no-special-chars",
		"",
		"$(echo pwned)",
		"a'b'c",
	}
	for _, want := range cases {
		t.Run(want, func(t *testing.T) {
			quoted := shellQuote(want)
			out, err := exec.Command("sh", "-c", "printf '%s' "+quoted).Output()
			if err != nil {
				t.Fatalf("sh -c with quoted string %q failed: %v", quoted, err)
			}
			if got := string(out); got != want {
				t.Errorf("shellQuote round-trip: got %q, want %q (quoted form was %q)", got, want, quoted)
			}
		})
	}
}

// ---- bareServerName ----------------------------------------------------------

// TestBareServerName covers ssh's own [USER@]SERVER splitting rule against
// real OpenSSH behaviour (verified against OpenSSH 10.2p1 via a ProxyCommand
// probe printing %n/%r): ssh splits on the LAST '@', not the first, so a
// Kerberos/GSSAPI-style principal like "alice@REALM@server1" keeps
// "alice@REALM" as the username and "server1" as the host.
func TestBareServerName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no at sign", "server1", "server1"},
		{"single at sign", "alice@server1", "server1"},
		{
			"multiple at signs matches ssh's last-@ split (verified OpenSSH 10.2p1)",
			"alice@REALM@server1", "server1",
		},
		{"trailing at sign with nothing after", "alice@", ""},
		{"leading at sign", "@server1", "server1"},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bareServerName(tc.in); got != tc.want {
				t.Errorf("bareServerName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---- ssh exec stub harness --------------------------------------------------

// installSSHStub writes a tiny POSIX shell script that records its argv to
// argvFile (one arg per line) and exits with exitCode. It points the
// package-level sshBinary var at the stub and restores it on cleanup. Tests
// using this helper must not run in parallel with each other (sshBinary is a
// shared package var).
func installSSHStub(t *testing.T, argvFile string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "ssh")
	script := "#!/bin/sh\n:> \"" + argvFile + "\"\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> \"" + argvFile + "\"; done\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("write ssh stub: %v", err)
	}
	old := sshBinary
	sshBinary = stub
	t.Cleanup(func() { sshBinary = old })
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func readArgvFile(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read argv file: %v", err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// findFlagValue returns the value that immediately follows a given -o flag
// value prefix (e.g. "ProxyCommand=") anywhere in argv, or "" if absent.
func findFlagValue(argv []string, prefix string) string {
	for i, a := range argv {
		if a == "-o" && i+1 < len(argv) && strings.HasPrefix(argv[i+1], prefix) {
			return strings.TrimPrefix(argv[i+1], prefix)
		}
	}
	return ""
}

// ---- config-mode tests -------------------------------------------------------

func TestSSH_ConfigMode_GeneratesProxyCommandAndHostKeyAlias(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 0)

	err := runVerb([]string{"--config", path, "ssh", "alice@server1"})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}

	argv := readArgvFile(t, argvFile)
	t.Logf("argv: %#v", argv)

	proxyCmd := findFlagValue(argv, "ProxyCommand=")
	if proxyCmd == "" {
		t.Fatal("no -o ProxyCommand=... found in argv")
	}
	if !strings.Contains(proxyCmd, "stdio %n ssh") {
		t.Errorf("ProxyCommand %q does not contain 'stdio %%n ssh'", proxyCmd)
	}
	if strings.Contains(proxyCmd, "--server") || strings.Contains(proxyCmd, "--pin") {
		t.Errorf("config-mode ProxyCommand must not thread --server/--pin: %q", proxyCmd)
	}

	hostKeyAlias := findFlagValue(argv, "HostKeyAlias=")
	if hostKeyAlias != "server1" {
		t.Errorf("HostKeyAlias = %q, want %q (bare server name, no username)", hostKeyAlias, "server1")
	}

	// [USER@]SERVER must be passed straight through unchanged as the final arg.
	if len(argv) == 0 || argv[len(argv)-1] != "alice@server1" {
		t.Errorf("last argv element = %q, want %q (unchanged [USER@]SERVER passthrough)",
			argv[len(argv)-1], "alice@server1")
	}
}

func TestSSH_ConfigMode_DefaultsToSoleServer(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.only]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 0)

	if err := runVerb([]string{"--config", path, "ssh"}); err != nil {
		t.Fatalf("ssh: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	if len(argv) == 0 || argv[len(argv)-1] != "only" {
		t.Errorf("expected default-resolved server 'only' as final arg, got argv=%#v", argv)
	}
}

func TestSSH_ConfigMode_AmbiguousServers_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.a]
addr = "127.0.0.1:7001"
pin  = "`+pin+`"
[servers.b]
addr = "127.0.0.1:7002"
pin  = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "ssh"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for ambiguous servers, got %d: %v", exitCode(err), err)
	}
}

func TestSSH_ConfigMode_UnknownServer_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "ssh", "bogus"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for unknown server, got %d: %v", exitCode(err), err)
	}
}

// ---- flag (config-free) mode tests -------------------------------------------

func TestSSH_FlagMode_ThreadsServerAndPinIntoProxyCommand(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 0)

	err := runVerb([]string{
		"ssh", "--server", "192.0.2.10:443", "--pin", pin, "alice@server1",
	})
	if err != nil {
		t.Fatalf("ssh flag mode: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	proxyCmd := findFlagValue(argv, "ProxyCommand=")
	if !strings.Contains(proxyCmd, "--server") || !strings.Contains(proxyCmd, "192.0.2.10:443") {
		t.Errorf("ProxyCommand missing --server ADDR: %q", proxyCmd)
	}
	if !strings.Contains(proxyCmd, "--pin") {
		t.Errorf("ProxyCommand missing --pin: %q", proxyCmd)
	}
	hostKeyAlias := findFlagValue(argv, "HostKeyAlias=")
	if hostKeyAlias != "server1" {
		t.Errorf("HostKeyAlias = %q, want %q", hostKeyAlias, "server1")
	}
}

func TestSSH_FlagMode_RequiresServerLabel(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	err := runVerb([]string{"ssh", "--server", "192.0.2.10:443", "--pin", pin})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 when SERVER label is omitted in flag mode, got %d: %v", exitCode(err), err)
	}
}

func TestSSH_FlagMode_RequiresBothFlags(t *testing.T) {
	unsetQLEnvForTest(t)
	err := runVerb([]string{"ssh", "--server", "192.0.2.10:443", "server1"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 when only --server is given (no --pin), got %d: %v", exitCode(err), err)
	}
}

// ---- exit code passthrough ---------------------------------------------------

func TestSSH_ExitCodePassthrough(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 7)

	err := runVerb([]string{"--config", path, "ssh", "server1"})
	if err == nil {
		t.Fatal("expected an error for a non-zero ssh exit")
	}
	if got := exitCode(err); got != 7 {
		t.Errorf("exitCode = %d, want 7 (ssh's own exit code)", got)
	}
	// Guard against the exact defect the task calls out: reusing
	// errFinalExitCode's hardcoded "attach refused" message would be
	// misleading for a plain ssh failure that involved no attach and no
	// agent.
	if strings.Contains(err.Error(), "attach refused") {
		t.Errorf("ssh exit-code error must not say \"attach refused\" (no attach/agent was involved): %v", err)
	}
}

func TestSSH_MissingSSHBinary_Exit1(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	old := sshBinary
	sshBinary = filepath.Join(t.TempDir(), "no-such-ssh-binary")
	t.Cleanup(func() { sshBinary = old })

	err := runVerb([]string{"--config", path, "ssh", "server1"})
	if err == nil {
		t.Fatal("expected an error when ssh is missing from PATH")
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exitCode = %d, want 1 (ssh never started, not ssh's own exit code)", got)
	}
}

// ---- -- passthrough parsing ---------------------------------------------------

func TestSSH_DashDashPassthrough(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 0)

	err := runVerb([]string{"--config", path, "ssh", "server1", "--", "-v", "-t"})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-v -t server1") {
		t.Errorf("expected passthrough args '-v -t' before final 'server1', got argv=%#v", argv)
	}
}

// ---- disabled-server guard -----------------------------------------------------

// TestSSH_ConfigMode_DisabledServer_Exit3_NoExec pins the fix for the
// missing disabled-server check: ssh must refuse before ever exec'ing the
// system ssh binary, with the exact same exit code and remedy message that
// stdio already uses for the identical config state, so the two verbs agree.
func TestSSH_ConfigMode_DisabledServer_Exit3_NoExec(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
enabled = false
`)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 0)

	var stderrBuf strings.Builder
	root := newRootCmd()
	root.SetErr(&stderrBuf)
	root.SetArgs([]string{"--config", path, "ssh", "server1"})
	err := root.ExecuteContext(context.Background())

	if err == nil {
		t.Fatal("expected an error for a disabled server")
	}
	if got := exitCode(err); got != 3 {
		t.Errorf("exitCode = %d, want 3 (disabled server), err=%v", got, err)
	}
	wantMsg := `server "server1" is disabled; set enabled = true in the config to use it`
	if !strings.Contains(stderrBuf.String(), wantMsg) {
		t.Errorf("stderr = %q, want it to contain %q (must match stdio's message exactly)",
			stderrBuf.String(), wantMsg)
	}
	if strings.Contains(stderrBuf.String(), "Usage:") {
		t.Errorf("ssh disabled server: stderr must not contain a cobra usage dump; got:\n%s", stderrBuf.String())
	}
	if _, statErr := os.Stat(argvFile); statErr == nil {
		t.Error("ssh binary was exec'd for a disabled server; it must never run")
	}
}

func TestSSH_TooManyArgsBeforeDash_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "ssh", "server1", "extra"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for two args before any --, got %d: %v", exitCode(err), err)
	}
}
