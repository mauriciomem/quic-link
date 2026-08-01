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
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-t tmux attach -t mysession") {
		t.Errorf("expected '-t tmux attach -t mysession' passthrough, got argv=%#v", argv)
	}
	if !strings.HasSuffix(joined, "server1") {
		t.Errorf("expected final arg 'server1' (unchanged SERVER), got argv=%#v", argv)
	}
	hostKeyAlias := findFlagValue(argv, "HostKeyAlias=")
	if hostKeyAlias != "server1" {
		t.Errorf("HostKeyAlias = %q, want %q", hostKeyAlias, "server1")
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
