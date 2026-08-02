package main

import (
	"context"
	"strings"
	"testing"
)

// ---- F1: the flags.Changed(...) gate must recognize the new flags --------

// TestAgentSSHAddrAloneSynthesizesAgentConfig is the single most important
// test in this slice. It invokes agent with --ssh-addr ALONE — no --listen,
// no --authorized-client — against a config file with no [agent] table.
//
// Before the fix, agent.go's flags.Changed(...) gate only recognized
// "listen", "service-addr", "docker-addr", "key", and "authorized-client".
// Removing --service-addr without adding "ssh-addr" and "route" to that list
// would leave agentCfg nil, and validateAgent would report the misleading
// "[agent] block is required for the agent role" — even though the user DID
// supply an agent flag. The real reason the command should fail is the
// empty authorized_clients list, and that is what the error must say.
//
// A test that also sets --listen would pass whether or not this gate is
// correct, and therefore proves nothing; this test deliberately omits it.
func TestAgentSSHAddrAloneSynthesizesAgentConfig(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("HOME", t.TempDir())

	path := writeTestConfig(t, `
schema = 1
`)
	err := runVerb([]string{"--config", path, "agent", "--ssh-addr", "tcp://127.0.0.1:2222"})
	if err == nil {
		t.Fatal("expected an error (no authorized clients supplied)")
	}
	if strings.Contains(err.Error(), "[agent] block is required") {
		t.Fatalf("regression: --ssh-addr alone did not synthesize an empty agent config; got the misleading missing-block message: %v", err)
	}
	if !strings.Contains(err.Error(), "authorized_clients") {
		t.Fatalf("expected the error to mention authorized_clients (the real reason), got: %v", err)
	}
}

// TestAgentRouteAloneSynthesizesAgentConfig is --route's counterpart to the
// test above, exercising the same gate via a different flag.
func TestAgentRouteAloneSynthesizesAgentConfig(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("HOME", t.TempDir())

	path := writeTestConfig(t, `
schema = 1
`)
	err := runVerb([]string{"--config", path, "agent", "--route", "pg-app=tcp://127.0.0.1:5432"})
	if err == nil {
		t.Fatal("expected an error (no authorized clients supplied)")
	}
	if strings.Contains(err.Error(), "[agent] block is required") {
		t.Fatalf("regression: --route alone did not synthesize an empty agent config; got the misleading missing-block message: %v", err)
	}
	if !strings.Contains(err.Error(), "authorized_clients") {
		t.Fatalf("expected the error to mention authorized_clients (the real reason), got: %v", err)
	}
}

// ---- F2: --service-addr's old default is still covered ------------------

// TestAgentSSHRouteDefaultsWithNoOverride verifies that with no --ssh-addr
// flag, no --route ssh=... flag, and no config [agent.routes] entry, the
// agent still resolves normally (router.New's own built-in tcp://127.0.0.1:22
// seed covers it — removing --service-addr's default loses nothing).
func TestAgentSSHRouteDefaultsWithNoOverride(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	pin := mustTestPin(t)
	keyPath := tmp + "/key.pem"
	if err := runVerb([]string{"keygen", "--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediate cancel; we only care that resolution succeeds

	root := newRootCmd()
	root.SetArgs([]string{
		"agent",
		"--listen", "127.0.0.1:0",
		"--key", keyPath,
		"--authorized-client", pin,
	})
	err := root.ExecuteContext(ctx)
	if exitCode(err) == 2 {
		t.Errorf("agent with no ssh override should not fail at resolution (exit 2): %v", err)
	}
}

// ---- Item 5: mutual exclusion ---------------------------------------------

func TestAgentSSHAddrAndRouteSSHIsUsageError(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
`)
	err := runVerb([]string{
		"--config", path, "agent",
		"--listen", "127.0.0.1:0",
		"--authorized-client", pin,
		"--ssh-addr", "tcp://127.0.0.1:2222",
		"--route", "ssh=tcp://127.0.0.1:3333",
	})
	if exitCode(err) != 2 {
		t.Fatalf("expected exit 2 for --ssh-addr + --route ssh=..., got %d: %v", exitCode(err), err)
	}
}

func TestAgentDockerAddrAndRouteDockerIsUsageError(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
`)
	err := runVerb([]string{
		"--config", path, "agent",
		"--listen", "127.0.0.1:0",
		"--authorized-client", pin,
		"--docker-addr", "unix:///var/run/docker.sock",
		"--route", "docker=unix:///var/run/docker2.sock",
	})
	if exitCode(err) != 2 {
		t.Fatalf("expected exit 2 for --docker-addr + --route docker=..., got %d: %v", exitCode(err), err)
	}
}

// A --route for an unrelated name alongside --ssh-addr must NOT be treated
// as a conflict — only the same route name triggers the usage error.
func TestAgentSSHAddrAndUnrelatedRouteIsFine(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	pin := mustTestPin(t)
	keyPath := tmp + "/key.pem"
	if err := runVerb([]string{"keygen", "--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	root := newRootCmd()
	root.SetArgs([]string{
		"agent",
		"--listen", "127.0.0.1:0",
		"--key", keyPath,
		"--authorized-client", pin,
		"--ssh-addr", "tcp://127.0.0.1:2222",
		"--route", "pg-app=tcp://127.0.0.1:5432",
	})
	err := root.ExecuteContext(ctx)
	if exitCode(err) == 2 {
		t.Errorf("--ssh-addr with an unrelated --route should not be a usage error: %v", err)
	}
}

// ---- --service-addr must no longer exist ----------------------------------

func TestAgentServiceAddrFlagRemoved(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
`)
	// A cancelled context guards against the case this test exists to catch
	// regressing back to: if --service-addr is still a recognized flag, flag
	// parsing succeeds and the agent would actually bind and block forever
	// waiting for connections, hanging the test instead of failing it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runVerbCtx(ctx, []string{
		"--config", path, "agent",
		"--listen", "127.0.0.1:0",
		"--authorized-client", pin,
		"--service-addr", "127.0.0.1:22",
	})
	if exitCode(err) != 2 {
		t.Fatalf("expected exit 2 (unknown flag) for --service-addr, got %d: %v", exitCode(err), err)
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("expected an unknown-flag error, got: %v", err)
	}
}
