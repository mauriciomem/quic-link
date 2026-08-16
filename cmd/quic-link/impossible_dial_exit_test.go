package main

// A daemon asked to reach an address it could never reach must say so and stop,
// with the exit code reserved for a value that is wrong on its face. The
// alternative it replaced was a process that ran indefinitely reporting that it
// was connecting.
//
// Both ways of naming a server are covered, because the command line replaces
// the settings file's list of servers rather than adding to it, so a check that
// only read the file would miss half the ways in.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeDaemonConfig writes a settings file naming one server, and returns its
// path along with the pin used, so a caller can reuse the pin on the command
// line.
func writeDaemonConfig(t *testing.T, addr string) (cfgPath, pin string) {
	t.Helper()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id.pem")
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pin = mustTestPin(t)

	cfgPath = filepath.Join(dir, "config.toml")
	body := "[identity]\nkey_file = " + quoted(keyPath) + "\n\n" +
		"[servers.web]\naddr = " + quoted(addr) + "\npin = " + quoted(pin) + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, pin
}

// quoted renders a value for a settings file.

func quoted(s string) string { return "\"" + s + "\"" }

func TestDaemonRefusesAnImpossibleAddressFromTheSettingsFile(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"unparseable", "this is not an address at all"},
		{"IPv6 literal", "[fd3e:5c82:9b1a:1::20]:7443"},
	}

	for _, tc := range cases {
		cfgPath, _ := writeDaemonConfig(t, tc.addr)

		err := runVerb([]string{"daemon", "--config", cfgPath})
		if err == nil {
			t.Errorf("%s: daemon accepted %q and kept running; an address that can never work "+
				"must stop it", tc.name, tc.addr)
			continue
		}
		if got := exitCode(err); got != 2 {
			t.Errorf("%s: exit code %d, want 2 — an address that is wrong on its face is the "+
				"same kind of mistake as any other bad setting: %v", tc.name, got, err)
		}
		if !strings.Contains(err.Error(), tc.addr) {
			t.Errorf("%s: message does not quote the address the operator has to fix: %v",
				tc.name, err)
		}
		if !strings.Contains(err.Error(), "web") {
			t.Errorf("%s: message does not name the server: %v", tc.name, err)
		}
	}
}

func TestDaemonRefusesAnImpossibleAddressGivenOnTheCommandLine(t *testing.T) {
	cfgPath, pin := writeDaemonConfig(t, "192.0.2.10:7443")

	err := runVerb([]string{
		"daemon", "--config", cfgPath,
		"--server-add", "flagged=[fd3e:5c82:9b1a:1::20]:7443",
		"--server-pin", "flagged=" + pin,
	})
	if err == nil {
		t.Fatal("daemon accepted an impossible address supplied on the command line; the " +
			"flags replace the settings file's servers, so they need the same check")
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exit code %d, want 2: %v", got, err)
	}
	if !strings.Contains(err.Error(), "flagged") {
		t.Errorf("message does not name the server given on the command line: %v", err)
	}
}

// TestAgentRefusesAnImpossibleClientAddress covers the other end of the same
// arrangement. When the server side is the one that connects out, it retries
// indefinitely for the same good reason the daemon does, and had the same
// problem: an address that can never work was retried alongside the ones that
// might.
func TestAgentRefusesAnImpossibleClientAddress(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id.pem")
	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.toml")
	body := "[identity]\nkey_file = " + quoted(keyPath) + "\n\n" +
		"[agent]\ndial = " + quoted("[fd3e:5c82:9b1a:1::20]:7443") + "\n" +
		"authorized_clients = [" + quoted(mustTestPin(t)) + "]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// The refusal has to be immediate, so the call is given a deadline of its
	// own. Without one, an agent that failed to refuse would sit in its retry
	// loop until the whole package ran out of time, and the report would be a
	// stalled run rather than this test saying what went wrong.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runVerbCtx(ctx, []string{"agent", "--config", cfgPath}) }()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the agent neither refused the address nor returned; it is retrying an address " +
			"that can never work")
	}

	if err == nil {
		t.Fatal("the agent accepted an address it can never reach and began retrying it")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the agent ran until its deadline instead of refusing straight away: %v", err)
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exit code %d, want 2: %v", got, err)
	}
	if !strings.Contains(err.Error(), "fd3e:5c82:9b1a:1::20") {
		t.Errorf("message does not quote the address: %v", err)
	}
}
