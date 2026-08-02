package main

// reverse_guard_test.go covers the unscoped daemon path against a reverse-mode
// server. Every other verb (ping, stdio, agent, and the scoped
// daemon --server NAME / connect alias) already refuses a listen-mode server
// cleanly and is already tested; plain "daemon" with no --server flag was the
// one gap, and nothing covered it.
//
// The invocation shape is the whole point of these tests: they must call
// daemon with NO --server flag. A test that passes --server NAME exercises the
// scoped path, which already refused correctly, and would pass whether or not
// the unscoped defect exists.

import (
	"context"
	"strings"
	"testing"
)

// oneReverseServerConfig writes a config whose only server is reverse-mode:
// listen set, addr absent. config.Load accepts this shape deliberately, since
// it is exactly what a reverse-mode server looks like.
func oneReverseServerConfig(t *testing.T) string {
	t.Helper()
	pin := mustTestPin(t)
	return writeTestConfig(t, `
schema = 1
[servers.rev]
listen = ":7443"
pin    = "`+pin+`"
`)
}

// TestDaemonUnscoped_ReverseServer_ExitsTwo is the regression test for the
// defect: plain "daemon" with no --server flag against a reverse-mode server
// must refuse at startup, exit 2, with the same message shape the scoped path
// already gives.
//
// Pre-fix failure mode: the guard lived only inside the scoped branch, so the
// unscoped invocation skipped it entirely, built a dial entry with an empty
// address, and retried forever. The test failed by observing anything other
// than exit 2 with "not yet supported" — in practice a daemon that started up
// and ran until its context was cancelled.
func TestDaemonUnscoped_ReverseServer_ExitsTwo(t *testing.T) {
	unsetQLEnvForTest(t)
	path := oneReverseServerConfig(t)

	// A cancelled context bounds the pre-fix behaviour: without it, the
	// unfixed daemon runs until killed. After the fix the guard returns
	// before any I/O, so the context is never consulted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runVerbCtx(ctx, []string{"--config", path, "daemon"})
	if exitCode(err) != 2 {
		t.Errorf("unscoped daemon against reverse-mode server: want exit 2, got %d: %v",
			exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("error should mention 'not yet supported', got: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "rev") {
		t.Errorf("error should name the offending server, got: %v", err)
	}
}

// TestDaemonUnscoped_ReverseServerAmongForward_ExitsTwo covers the realistic
// config: a working forward-mode server alongside a reverse-mode one. The
// unscoped daemon manages all enabled servers, so it must refuse rather than
// silently manage the forward one and spin on the reverse one.
func TestDaemonUnscoped_ReverseServerAmongForward_ExitsTwo(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.fwd]
addr = "127.0.0.1:19970"
pin  = "`+pin+`"

[servers.rev]
listen = ":7443"
pin    = "`+pin+`"
`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runVerbCtx(ctx, []string{"--config", path, "daemon"})
	if exitCode(err) != 2 {
		t.Errorf("unscoped daemon with a reverse-mode server in the fleet: want exit 2, got %d: %v",
			exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "rev") {
		t.Errorf("error should name the reverse-mode server, got: %v", err)
	}
}

// TestDaemonUnscoped_DisabledReverseServer_NotRefused guards against
// over-refusal. A disabled server is not managed by the daemon at all, so a
// disabled reverse-mode entry must not block startup. The guard runs before
// any I/O, so whatever the daemon fails on afterwards (a missing identity key,
// an already-running owner) is irrelevant here: the only assertion is that the
// reverse-mode refusal is not what came back.
func TestDaemonUnscoped_DisabledReverseServer_NotRefused(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.fwd]
addr = "127.0.0.1:19971"
pin  = "`+pin+`"

[servers.revoff]
listen  = ":7443"
pin     = "`+pin+`"
enabled = false
`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runVerbCtx(ctx, []string{"--config", path, "daemon"})
	if err != nil && strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("a disabled reverse-mode server must not block the daemon; got: %v", err)
	}
}
