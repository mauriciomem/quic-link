package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---- --config propagation into the generated ProxyCommand -------------------
//
// Field-found defect (Step 1b.2b two-host campaign): ssh did not thread the
// parent invocation's explicitly-set --config into the ProxyCommand it
// generates, so the spawned stdio child fell back to the default config path
// and could not find a server that exists only in the config the user
// explicitly selected. This mirrors the existing --server/--pin threading:
// the child needs the parent's connection context, and --config is part of
// that context.

// TestSSH_ConfigMode_PropagatesExplicitConfigFlag pins the fix: when
// --config was explicitly given on the parent invocation, the generated
// ProxyCommand must contain a --config token followed by the same,
// shell-quoted, path.
func TestSSH_ConfigMode_PropagatesExplicitConfigFlag(t *testing.T) {
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

	err := runVerb([]string{"--config", path, "ssh", "server1"})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	proxyCmd := findFlagValue(argv, "ProxyCommand=")
	if proxyCmd == "" {
		t.Fatal("no -o ProxyCommand=... found in argv")
	}

	wantToken := "--config " + shellQuote(path)
	if !strings.Contains(proxyCmd, wantToken) {
		t.Errorf("ProxyCommand %q does not contain %q (the explicitly-set "+
			"--config was not threaded through, so the spawned stdio child "+
			"would read the default config instead of the one the user "+
			"selected)", proxyCmd, wantToken)
	}
}

// TestSSH_ConfigMode_NoExplicitConfig_OmitsConfigFlag guards the opposite
// direction: when the user did NOT pass --config (the common case, default
// config path), the generated ProxyCommand must contain no --config token
// at all. Synthesizing one would hardcode a resolved default path into the
// ProxyCommand and change behaviour for every user who relies on the
// default location.
func TestSSH_ConfigMode_NoExplicitConfig_OmitsConfigFlag(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	pin := mustTestPin(t)
	// Write the config at the DEFAULT path so ssh's own config-based
	// resolution succeeds without --config being passed at all.
	defaultDir := filepath.Join(tmp, ".config", "quic-link")
	if err := os.MkdirAll(defaultDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	defaultPath := filepath.Join(defaultDir, "config.toml")
	content := "schema = 1\n[servers.server1]\naddr = \"127.0.0.1:7443\"\npin  = \"" + pin + "\"\n"
	if err := os.WriteFile(defaultPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write default config: %v", err)
	}

	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 0)

	err := runVerb([]string{"ssh", "server1"})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	proxyCmd := findFlagValue(argv, "ProxyCommand=")
	if proxyCmd == "" {
		t.Fatal("no -o ProxyCommand=... found in argv")
	}
	if strings.Contains(proxyCmd, "--config") {
		t.Errorf("ProxyCommand %q must not contain --config when the user "+
			"never set it (would hardcode a resolved default path)", proxyCmd)
	}
}

// TestBuildProxyCommand_ConfigPathWithSpaces_RoundTripsThroughShell proves
// the --config path is quoted the same way the binary path already is (the
// same technique TestShellQuoteRoundTrips_PathWithSpaces pins), by actually
// running the generated command line through a real shell rather than
// comparing strings. A stub "print-argv" binary stands in for quic-link
// itself so the real argv a shell would hand to it is observable.
func TestBuildProxyCommand_ConfigPathWithSpaces_RoundTripsThroughShell(t *testing.T) {
	base := t.TempDir()
	configWithSpaces := filepath.Join(base, "dir with spaces", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configWithSpaces), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, "print-argv")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	proxyCmd := buildProxyCommand(stub, false, "", "", configWithSpaces)

	out, err := exec.Command("sh", "-c", proxyCmd).Output()
	if err != nil {
		t.Fatalf("sh -c %q: %v", proxyCmd, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	t.Logf("shell-parsed argv: %#v", lines)

	idx := indexOf(lines, "--config")
	if idx == -1 || idx+1 >= len(lines) {
		t.Fatalf("no --config token found in shell-parsed argv %#v (proxyCmd=%q)", lines, proxyCmd)
	}
	if got := lines[idx+1]; got != configWithSpaces {
		t.Errorf("shell round-trip of the quoted config path = %q, want %q (proxyCmd=%q)",
			got, configWithSpaces, proxyCmd)
	}
}

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

// sshDestination replicates real ssh's own destination-parsing rule closely
// enough for these tests: ssh's grammar is "ssh [options] destination
// [command]", so it scans argv left to right and treats the FIRST
// non-option token as the destination. This helper skips "-o" together with
// its following value, and skips any other bare flag token (one that
// starts with "-", consuming no value of its own — sufficient for the only
// other flags these tests exercise, "-v" and "-t"), then returns the first
// remaining token.
//
// This exists because asserting merely that a destination string appears
// SOMEWHERE in argv cannot distinguish a correctly-ordered argv from a
// broken one where the same string is misparsed as part of a remote
// command — exactly the failure mode a field-found defect slipped through
// under (destination appended after the passthrough instead of before it).
func sshDestination(argv []string) string {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "-o" {
			i++ // skip the value that belongs to -o
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue // a bare flag with no value of its own, e.g. -v, -t
		}
		return a
	}
	return ""
}

// indexOf returns the index of the first element in argv equal to s, or -1.
func indexOf(argv []string, s string) int {
	for i, a := range argv {
		if a == s {
			return i
		}
	}
	return -1
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
	t.Logf("argv: %#v", argv)

	// ssh's own grammar is "ssh [options] destination [command]": the
	// destination must come BEFORE ssh's own passthrough flags, not after,
	// or a real ssh would misparse a remote command in the passthrough as
	// the destination (see TestSSH_DashDashPassthrough_RemoteCommand). A
	// plain substring check on the joined argv is not reliable here: the
	// generated "-o HostKeyAlias=server1" token itself contains the literal
	// substring "server1 -v -t" is NOT guaranteed to be absent even under
	// the broken ordering, so this asserts on argv INDICES instead, the
	// same technique the remote-command test below uses.
	if got := sshDestination(argv); got != "server1" {
		t.Errorf("ssh would parse the destination as %q, want %q; argv=%#v", got, "server1", argv)
	}
	destIdx := indexOf(argv, "server1")
	if destIdx == -1 {
		t.Fatalf("destination %q not found anywhere in argv=%#v", "server1", argv)
	}
	if destIdx+2 >= len(argv) || argv[destIdx+1] != "-v" || argv[destIdx+2] != "-t" {
		t.Errorf("expected destination 'server1' immediately followed by passthrough '-v' '-t', got argv=%#v", argv)
	}
}

// TestSSH_DashDashPassthrough_RemoteCommand pins the exact field-found
// defect: a passthrough containing a remote COMMAND (not just ssh's own
// flags) must not be misparsed as the destination. Real ssh's grammar is
// "ssh [options] destination [command]"; before the fix, this verb appended
// the destination AFTER the passthrough, so real ssh parsed the
// passthrough's first non-option token ("echo hi", quoted as one argv
// element) — or, for -o-prefixed passthrough, whatever followed the -o
// pairs — as the destination instead of "server1".
func TestSSH_DashDashPassthrough_RemoteCommand(t *testing.T) {
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

	err := runVerb([]string{
		"--config", path, "ssh", "server1", "--",
		"-o", "BatchMode=yes", "echo hi",
	})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	t.Logf("argv: %#v", argv)

	if got := sshDestination(argv); got != "server1" {
		t.Errorf("ssh would parse the destination as %q, want %q (the remote command "+
			"must not be mistaken for the destination); argv=%#v", got, "server1", argv)
	}

	destIdx := indexOf(argv, "server1")
	if destIdx == -1 {
		t.Fatalf("destination %q not found anywhere in argv=%#v", "server1", argv)
	}
	cmdIdx := indexOf(argv, "echo hi")
	if cmdIdx == -1 {
		t.Fatalf("remote command %q not found in argv=%#v", "echo hi", argv)
	}
	if cmdIdx < destIdx {
		t.Errorf("remote command at index %d appears BEFORE the destination at index %d; "+
			"ssh's grammar requires the destination first, argv=%#v", cmdIdx, destIdx, argv)
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
