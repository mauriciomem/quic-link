package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestAttach_DelegatesToSSH verifies attach SERVER SESSION generates exactly
// the sugar the contract specifies: "ssh SERVER -- -t tmux attach -t
// SESSION". It drives the real cobra command end-to-end through the ssh
// stub so the assertion is on the actual argv ssh would receive, not on an
// internal representation.
func TestAttach_DelegatesToSSH(t *testing.T) {
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

	err := runVerb([]string{"--config", path, "attach", "server1", "mysession"})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	argv := readArgvFile(t, argvFile)

	// The destination must precede the passthrough (real ssh's grammar is
	// "ssh [options] destination [command]"), so "server1" is found as its
	// own argv token — not by a suffix/substring check on the joined
	// string, which is what let the field-found ordering defect through
	// undetected (see TestAttach_DestinationParsedAsServer_NotTmux).
	destIdx := indexOf(argv, "server1")
	if destIdx == -1 {
		t.Fatalf("destination %q not found anywhere in argv=%#v", "server1", argv)
	}
	wantTail := []string{"-t", "tmux", "attach", "-t", "mysession"}
	if destIdx+1+len(wantTail) != len(argv) {
		t.Fatalf("expected destination 'server1' immediately followed by %v with nothing after, got argv=%#v", wantTail, argv)
	}
	for i, want := range wantTail {
		if got := argv[destIdx+1+i]; got != want {
			t.Errorf("passthrough element %d = %q, want %q; argv=%#v", i, got, want, argv)
		}
	}
	hostKeyAlias := findFlagValue(argv, "HostKeyAlias=")
	if hostKeyAlias != "server1" {
		t.Errorf("HostKeyAlias = %q, want %q", hostKeyAlias, "server1")
	}
}

// TestAttach_DestinationParsedAsServer_NotTmux pins the exact field-found
// defect for attach, which the task calls "fully broken today": before the
// fix, attach's synthesized passthrough ("-t", "tmux", "attach", "-t",
// session) was appended BEFORE the destination, so a real ssh would parse
// "tmux" — the second element of attach's own synthesized remote command —
// as the destination instead of the actual server, and the real server name
// would be read by ssh as part of the remote command.
func TestAttach_DestinationParsedAsServer_NotTmux(t *testing.T) {
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

	err := runVerb([]string{"--config", path, "attach", "server1", "mysession"})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	t.Logf("argv: %#v", argv)

	if got := sshDestination(argv); got != "server1" {
		t.Errorf("ssh would parse the destination as %q, want %q (must not be the literal "+
			"\"tmux\" from attach's own synthesized command); argv=%#v", got, "server1", argv)
	}
}

// TestAttach_ExitCodePassthrough verifies attach's exit code is ssh's own,
// exactly like the ssh verb itself.
func TestAttach_ExitCodePassthrough(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	argvFile := filepath.Join(t.TempDir(), "argv")
	installSSHStub(t, argvFile, 3)

	err := runVerb([]string{"--config", path, "attach", "server1", "mysession"})
	if got := exitCode(err); got != 3 {
		t.Errorf("exitCode = %d, want 3 (ssh's own exit code), err=%v", got, err)
	}
}

// TestAttach_UnknownServer_Exit2 verifies attach reuses ssh's own server
// resolution (and thus its exit-2 behaviour), rather than reimplementing it.
func TestAttach_UnknownServer_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.server1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)
	err := runVerb([]string{"--config", path, "attach", "bogus", "mysession"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for unknown server, got %d: %v", exitCode(err), err)
	}
}

// TestAttach_WrongArgCount_Exit2 verifies the cobra arg-count fix covers this
// new verb too.
func TestAttach_WrongArgCount_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	err := runVerb([]string{"attach", "server1"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for missing SESSION arg, got %d: %v", exitCode(err), err)
	}
}

// TestAttach_PropagatesExplicitConfigFlag pins that attach inherits the
// --config propagation fix: it delegates entirely to runSSHCore, the same
// function the ssh verb calls, so an explicitly-set --config on the parent
// invocation must reach the generated ProxyCommand here too, not just via
// the ssh verb directly.
func TestAttach_PropagatesExplicitConfigFlag(t *testing.T) {
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

	err := runVerb([]string{"--config", path, "attach", "server1", "mysession"})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	argv := readArgvFile(t, argvFile)
	proxyCmd := findFlagValue(argv, "ProxyCommand=")
	if proxyCmd == "" {
		t.Fatal("no -o ProxyCommand=... found in argv")
	}

	wantToken := "--config " + shellQuote(path)
	if !strings.Contains(proxyCmd, wantToken) {
		t.Errorf("attach's ProxyCommand %q does not contain %q; attach delegates "+
			"to runSSHCore and must inherit the same --config threading as ssh",
			proxyCmd, wantToken)
	}
}
