package main

import (
	"strings"
	"testing"
)

// TestServerFlags_DefineAServerWithNoSettingsFile pins the point of the whole
// feature: a daemon can be given a server entirely on the command line. It gets
// as far as trying to reach the address, which is the proof that the server was
// accepted — resolution and validation are behind it by then.
func TestServerFlags_DefineAServerWithNoSettingsFile(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)

	err := runDaemonBriefly(t,
		"daemon",
		"--server-add", "web1=127.0.0.1:47999",
		"--server-pin", "web1="+pin,
	)
	// It must not be refused for having nothing to manage, nor for a bad name or
	// pin. Any failure here should be about the world, not the command.
	if err != nil {
		for _, mustNotSay := range []string{
			"no servers to manage", "not found in config", "expected NAME=VALUE",
		} {
			if strings.Contains(err.Error(), mustNotSay) {
				t.Fatalf("a flag-defined server was not accepted: %v", err)
			}
		}
	}
}

// TestServerFlags_RejectMalformedValues pins that every way of getting the pair
// wrong is a usage error, reported against what the user typed.
func TestServerFlags_RejectMalformedValues(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no equals", []string{"--server-add", "web1"}, "expected NAME=VALUE"},
		{"empty name", []string{"--server-add", "=1.2.3.4:7443"}, "must not be empty"},
		{"empty value", []string{"--server-add", "web1="}, "must not be empty"},
		{"name is not a label", []string{"--server-add", "web_1=1.2.3.4:7443"}, "hostname"},
		{"uppercase name", []string{"--server-add", "WEB1=1.2.3.4:7443"}, "lowercase"},
		{
			"duplicate name",
			[]string{"--server-add", "web1=1.2.3.4:7443", "--server-add", "web1=5.6.7.8:7443"},
			"duplicate",
		},
		{
			"pin with no address",
			[]string{"--server-pin", "web1=" + pin},
			"no --server-add defines it",
		},
		{
			"address with no pin",
			[]string{"--server-add", "web1=1.2.3.4:7443"},
			"no --server-pin gives its pin",
		},
		{
			"pin is not a pin",
			[]string{"--server-add", "web1=1.2.3.4:7443", "--server-pin", "web1=not-a-pin"},
			"invalid --server-pin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			err := runVerb(append([]string{"daemon"}, tc.args...))
			if exitCode(err) != 2 {
				t.Fatalf("want a usage error (exit 2), got %d: %v", exitCode(err), err)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestServerFlags_ReplaceRatherThanMergeWithTheSettingsFile pins the precedence
// rule. Somebody naming one server means that server: merging would hand them
// their whole configured fleet as well, with every session dialled and every name
// answered, which is the opposite of what they asked for.
func TestServerFlags_ReplaceRatherThanMergeWithTheSettingsFile(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.fromfile]
addr = "127.0.0.1:47998"
pin  = "`+pin+`"
`)

	// Scoping to the file's server must now fail: the flags replaced it.
	err := runDaemonBriefly(t,
		"--config", path, "daemon",
		"--server-add", "fromflag=127.0.0.1:47997",
		"--server-pin", "fromflag="+pin,
		"--server", "fromfile",
	)
	if err == nil || !strings.Contains(err.Error(), "fromfile") {
		t.Errorf("the file's server should no longer be available to scope to, got: %v", err)
	}
	// And the flag's server must be scopeable.
	err = runDaemonBriefly(t,
		"--config", path, "daemon",
		"--server-add", "fromflag=127.0.0.1:47997",
		"--server-pin", "fromflag="+pin,
		"--server", "fromflag",
	)
	if err != nil && strings.Contains(err.Error(), "not found in config") {
		t.Errorf("the flag-defined server must be scopeable: %v", err)
	}
}

// TestDaemon_WithNothingToManageSaysWhatIsMissing pins the end of a silent
// no-op. An owner with no servers used to start anyway: naming sockets up, local
// API answering, not one tunnel — indistinguishable from a misconfiguration.
func TestDaemon_WithNothingToManageSaysWhatIsMissing(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	path := writeTestConfig(t, "schema = 1\n")

	// Bounded on purpose. If the refusal is ever removed, this daemon would start
	// and hold the socket until the whole package timed out — a hang that names no
	// test, which is the failure shape this phase's first step existed to end. A
	// cancelled run returns promptly and fails the assertion below by name.
	err := runDaemonBriefly(t, "--config", path, "daemon")
	if exitCode(err) != 2 {
		t.Fatalf("want a usage error (exit 2), got %d: %v", exitCode(err), err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "no servers to manage") {
		t.Errorf("it should say there is nothing to manage, got: %v", err)
	}
	// Both ways of defining one must be offered: naming only the file would be
	// wrong for somebody using flags, and the reverse for somebody using a file.
	if !strings.Contains(msg, "servers.web1") {
		t.Errorf("it should show the settings entry to add, got: %v", err)
	}
	if !strings.Contains(msg, "--server-add") {
		t.Errorf("it should also show the flags, got: %v", err)
	}
	if !strings.Contains(msg, path) {
		t.Errorf("it should name the settings file it read, got: %v", err)
	}
}

// TestStdio_AcceptsAServerOnlyTheDaemonKnows pins a defect found on a real
// machine, not here: a server defined on a daemon's command line was reported by
// status, listed by status --routes and reachable by name in a browser, and yet
// the verb that carries a single stream refused it — because that verb asked the
// settings file directly, and a server defined on a command line is in no file.
//
// A settings entry is only needed to dial an agent directly. The daemon path
// needs the name and nothing more, so a name the daemon manages has to be enough
// on its own. Without this, the feature was two thirds implemented in a way no
// in-process test noticed.
func TestStdio_AcceptsAServerOnlyTheDaemonKnows(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	path := writeTestConfig(t, "schema = 1\n")

	// What this test can reach is the message. Whether a name the daemon manages is
	// then ACCEPTED needs a running daemon managing one, which is a two-process
	// arrangement this package cannot build; that half is proven against a real
	// binary on a real machine instead, and the note in the phase history says so.
	// Mutating the daemon lookup away therefore does not fail here — recorded
	// rather than hidden, because a control nobody can trip is worth knowing about.
	//
	// With no daemon and no settings entry, the message must name both places it
	// looked rather than only the file.
	err := runVerb([]string{"--config", path, "stdio", "web1", "ssh"})
	if exitCode(err) != 2 {
		t.Fatalf("want a usage error (exit 2), got %d: %v", exitCode(err), err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "settings") {
		t.Errorf("the message should mention settings, got: %v", err)
	}
	if !strings.Contains(msg, "daemon") {
		t.Errorf("the message should also mention a running daemon, got: %v", err)
	}
}
