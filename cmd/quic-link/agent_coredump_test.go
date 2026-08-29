package main

// agent_coredump_test.go covers a regression: the agent verb must disable
// core dumps before it loads the Ed25519 identity key, the same protection
// daemon.Run already applies on its own startup path.
//
// @spec-handoff
//
// Interface under test: agentRun (cmd/quic-link/agent.go), through two
// package-level function variables it now calls through rather than calling
// the underlying functions directly: disableCoreDumpFunc (defaults to
// daemon.DisableCoreDump) and loadKeyFunc (defaults to identity.LoadKey).
// This follows the existing readMetaFunc precedent in
// internal/daemon/daemon.go — a test substitutes the variable to observe a
// call without depending on real, irreversible process-wide RLIMIT_CORE
// state (coredump_unix_test.go already establishes that state is
// irreversible within one test binary, which rules out asserting on real
// kernel state from this package's test suite).
//
// Expected behavior:
//   - agentRun calls disableCoreDumpFunc exactly once per invocation.
//   - That call happens before loadKeyFunc reads the private key — checked
//     here by recording the relative order of both calls in a shared slice,
//     rather than by reading real kernel state.
//
// Edge case: an agent invocation that fails validation before agentRun is
// ever reached (e.g. dial+listen both set) must not be interpreted as a
// regression in this guarantee — this test drives agentRun directly, not
// through the cobra command, so it exercises exactly the function whose
// ordering matters and nothing upstream of it.
//
// What this test cannot assert: it cannot prove real kernel RLIMIT_CORE
// state changed — see the file-level rationale above for why. Real
// kernel-state proof belongs to internal/daemon's existing
// coredump_unix_test.go / coredump_other_test.go, and to a manual
// /proc/<pid>/limits check against a running agent process (see the plan
// step's verification notes for that check).

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

// TestAgentRun_DisablesCoreDumpBeforeLoadingKey drives agentRun with
// disableCoreDumpFunc and loadKeyFunc both substituted, and confirms the
// core-dump call happened, and happened before the key-load call — recorded
// as an ordered event log rather than two independent booleans, since
// either event happening without the other in the right order is the
// actual defect this guards against.
//
// Pre-fix failure mode: agentRun never calls a core-dump-disabling function
// at all — disableCoreDump is called from exactly one site in the whole
// tree, internal/daemon/daemon.go:135, which the agent verb never reaches.
// With no fix, this test fails because the
// "coredump" event never appears in the log at all, not merely out of
// order — disableCoreDumpFunc does not yet exist as a seam agentRun calls
// through.
func TestAgentRun_DisablesCoreDumpBeforeLoadingKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	keyPath := filepath.Join(tmp, "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	var events []string

	origCoreDump := disableCoreDumpFunc
	disableCoreDumpFunc = func() error {
		events = append(events, "coredump")
		return nil
	}
	defer func() { disableCoreDumpFunc = origCoreDump }()

	origLoadKey := loadKeyFunc
	loadKeyFunc = func(path string) (ed25519.PrivateKey, error) {
		events = append(events, "loadkey")
		return origLoadKey(path)
	}
	defer func() { loadKeyFunc = origLoadKey }()

	clientPin := mustTestPin(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediate shutdown; this test cares about startup ordering only

	// The return value is not the point of this test (agent_bind_test.go
	// already covers agentRun's shutdown-error shapes); only the recorded
	// event order matters here.
	_ = agentRun(ctx, config.Agent{Listen: "127.0.0.1:0"}, keyPath, pinList{clientPin}, minimalIdentityCfg())

	if len(events) == 0 || events[0] != "coredump" {
		t.Fatalf("expected disableCoreDumpFunc to be called before loadKeyFunc; got event order %v", events)
	}
	coreDumpCalls := 0
	for _, e := range events {
		if e == "coredump" {
			coreDumpCalls++
		}
	}
	if coreDumpCalls != 1 {
		t.Errorf("disableCoreDumpFunc called %d times, want exactly 1", coreDumpCalls)
	}
}
