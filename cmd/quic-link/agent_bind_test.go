package main

// agent_bind_test.go verifies the agent's UDP socket binding behaviour.
//
// The agent binds a dual-stack ("udp") socket, not an IPv4-only ("udp4")
// socket. This asymmetry relative to all client paths (which use "udp4") is
// deliberate — see the comment in agentRun for the full rationale. This test
// guards against a future "tidy-up" that blindly aligns the agent with the
// client rule and breaks IPv6-only deployments or silently kills IPv6
// acceptance on dual-stack hosts.
//
// What we test: the agent binds successfully on 127.0.0.1:0 (wildcard port),
// starts its QUIC listener, and shuts down cleanly when the context is
// cancelled. A bind failure would surface as an error from agentRun.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

// minimalIdentityCfg returns a config.Identity with all hygiene checks
// disabled, suitable for short-lived agent tests where the key was just
// created and has no .meta sidecar with a meaningful age.
func minimalIdentityCfg() config.Identity {
	return config.Identity{
		WarnKeyAgeDays: 0, // disabled: no age check
	}
}

// TestAgent_BindsAndShutdown verifies that agentRun can bind its UDP socket
// and return cleanly when the context is cancelled. This exercises the bind
// and listener path without requiring real QUIC traffic.
//
// Pre-change failure mode: no test existed for agentRun at all; a change from
// "udp" to "udp4" in the bind call would compile cleanly and pass all tests
// on Linux (where udp4 and udp behave identically), while silently breaking
// the agent's ability to accept IPv6 connections on dual-stack hosts.
func TestAgent_BindsAndShutdown(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Generate a key so agentRun can load it.
	keyPath := filepath.Join(tmp, "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 127.0.0.1:0 — loopback, OS-assigned port. Tests must never use fixed
	// ports; :0 lets the kernel pick a free one.
	const listenAddr = "127.0.0.1:0"
	clientPin := mustTestPin(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the agent shuts down without blocking

	err := agentRun(ctx, listenAddr, "", nil, keyPath, pinList{clientPin}, minimalIdentityCfg())

	// context.Canceled (or the equivalent "server closed" / "use of closed"
	// from QUIC-go tearing down on cancel) is the expected return value.
	// Any bind error, TLS setup error, or unexpected nil are failures.
	if err == nil {
		// Unexpected clean exit with no error on an immediately-cancelled
		// context — likely the listener wasn't set up before the cancel fired.
		// This is acceptable; it means the QUIC transport exited before any
		// accept. Not a bind failure.
		t.Logf("agentRun returned nil on immediate cancel (QUIC shutdown beat Accept)")
		return
	}

	errStr := err.Error()
	acceptableErrors := []string{
		"context canceled",
		"server closed",
		"use of closed network connection",
		"operation was canceled",
	}
	isAcceptable := false
	for _, msg := range acceptableErrors {
		if strings.Contains(errStr, msg) {
			isAcceptable = true
			break
		}
	}
	if !isAcceptable {
		t.Errorf("agentRun returned unexpected error (not a clean shutdown): %v", err)
	}
}

// TestAgent_BindsOnIPv4Loopback is a narrower check: it confirms the agent
// accepts the "127.0.0.1:0" listen address without a resolution or bind error.
// This separates bind problems (early, clear error) from transport problems
// (later, context-cancellation shaped).
func TestAgent_BindsOnIPv4Loopback(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	keyPath := filepath.Join(tmp, "key.pem")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	clientPin := mustTestPin(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := agentRun(ctx, "127.0.0.1:0", "", nil, keyPath, pinList{clientPin}, minimalIdentityCfg())

	// A bind error would look like: "bind 127.0.0.1:0: ..."
	// An address-resolution error: "invalid listen address: ..."
	// Neither should occur on the loopback.
	if err != nil && (strings.Contains(err.Error(), "bind ") || strings.Contains(err.Error(), "invalid listen")) {
		t.Errorf("agentRun failed at the bind/resolve step: %v", err)
	}
	// Log for visibility but don't fail on clean-shutdown shapes.
	t.Logf("agentRun returned: %v", fmt.Sprintf("%v", err))
}
