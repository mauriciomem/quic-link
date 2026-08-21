package main

// The agent can now connect out to a client that waits, instead of waiting for
// one to connect to it. These cover the flag surface and the mutual exclusion,
// which is where a misconfiguration should be caught rather than at runtime.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runAgentBriefly(t *testing.T, args ...string) error {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	return runVerbCtx(ctx, args)
}

// TestAgentDialFlag_NoLongerRefused: reverse mode used to be rejected outright.
func TestAgentDialFlag_NoLongerRefused(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)

	err := runAgentBriefly(t, "agent", "--dial", "127.0.0.1:59999",
		"--authorized-client", pin, "--key", writeTestKey(t))
	if err != nil && strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("agent still refuses to connect out: %v", err)
	}
}

// TestAgentDialAndListen_MutuallyExclusive_Exit2: an address to connect to and
// an address to wait on are two different answers to the same question, so
// setting both is a configuration error, not a precedence puzzle.
func TestAgentDialAndListen_MutuallyExclusive_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)

	err := runAgentBriefly(t, "agent", "--dial", "127.0.0.1:59999", "--listen", "127.0.0.1:0",
		"--authorized-client", pin, "--key", writeTestKey(t))
	if exitCode(err) != 2 {
		t.Errorf("--dial with --listen: want exit 2, got %d: %v", exitCode(err), err)
	}
}

// TestAgentDialAlone_ReportsTheRealProblem: with --dial as the only flag and no
// config file, the complaint must be the missing authorized client, not a
// misleading claim that the whole agent block is absent. This is the same
// failure shape a previous flag addition shipped with.
func TestAgentDialAlone_ReportsTheRealProblem(t *testing.T) {
	unsetQLEnvForTest(t)
	// This asserts what happens with no configuration, so it must not find the
	// configuration of whoever is running it.
	detachHomeForTest(t)

	err := runAgentBriefly(t, "agent", "--dial", "127.0.0.1:59999")
	if err == nil {
		t.Fatal("agent --dial with no authorized clients should fail")
	}
	if strings.Contains(err.Error(), "[agent] block is required") {
		t.Errorf("misleading error: --dial was given, so the block is not what is missing: %v", err)
	}
	if !strings.Contains(err.Error(), "authorized_clients") {
		t.Errorf("error should name the missing authorized_clients, got: %v", err)
	}
}

// TestAgentDialFromConfig: the config key works without any flag, since a
// long-running agent is normally configured by file.
func TestAgentDialFromConfig(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[identity]
key_file = "`+writeTestKey(t)+`"

[agent]
dial               = "127.0.0.1:59998"
authorized_clients = ["`+pin+`"]
`)

	err := runAgentBriefly(t, "--config", path, "agent")
	if exitCode(err) == 2 {
		t.Errorf("a valid connect-out config should not be a usage error: %v", err)
	}
}

// writeTestKey generates a real identity key in a temp dir and returns its path.
func writeTestKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := runVerb([]string{"keygen", "--out", path}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return path
}
