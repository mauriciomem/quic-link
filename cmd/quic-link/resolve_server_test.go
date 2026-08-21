package main

import (
	"strings"
	"testing"
)

// TestRequireKnownServer_FallsBackToSettingsWithNoDaemon pins that working from
// a settings file is unchanged when nothing is running. The resolution asks a
// daemon first, and a daemon that is not there must not be read as proof that a
// server does not exist.
func TestRequireKnownServer_FallsBackToSettingsWithNoDaemon(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.web1]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)

	// A name in the file is accepted.
	err := runVerb([]string{"--config", path, "status", "--routes", "web1"})
	if err != nil && strings.Contains(err.Error(), "not found in config") {
		t.Errorf("a server in the settings file must still resolve with no daemon: %v", err)
	}

	// A name in neither place is refused, and says where it looked.
	err = runVerb([]string{"--config", path, "status", "--routes", "nosuch"})
	if exitCode(err) != 2 {
		t.Fatalf("an unknown server should be a usage error, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "not found in config") {
		t.Errorf("with no daemon the message should name the settings file, got: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "web1") {
		t.Errorf("it should list what is available, got: %v", err)
	}
}

// TestAutoSelectServer_NoServersAnywhereExplainsBothWays pins the message a
// person sees when nothing is defined at all. It has to name both ways of
// defining a server, because either is a valid way to run the tool and a message
// naming only the file would be wrong for somebody using flags.
func TestAutoSelectServer_NoServersAnywhereExplainsBothWays(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	path := writeTestConfig(t, "schema = 1\n")

	err := runVerb([]string{"--config", path, "status", "--routes"})
	if exitCode(err) != 2 {
		t.Fatalf("no servers anywhere should be a usage error, got %d: %v", exitCode(err), err)
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if !strings.Contains(msg, "servers.") {
		t.Errorf("the message should show the settings entry to add, got: %v", err)
	}
	if !strings.Contains(msg, "daemon") {
		t.Errorf("the message should also mention defining one on the command line, got: %v", err)
	}
}

// TestAutoSelectServer_OneServerIsChosenWithoutBeingNamed pins the convenience
// that already existed: with exactly one server there is nothing to disambiguate,
// so the verb acts on it.
func TestAutoSelectServer_OneServerIsChosenWithoutBeingNamed(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.only]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
`)

	err := runVerb([]string{"--config", path, "status", "--routes"})
	// With no daemon this cannot succeed, but it must fail for the daemon being
	// absent rather than for not knowing which server was meant.
	if err != nil && strings.Contains(err.Error(), "name one") {
		t.Errorf("with one server there is nothing to name: %v", err)
	}
}

// TestAutoSelectServer_SeveralServersAskRatherThanGuess pins that a fleet of
// more than one is never guessed at. Acting on a server the user did not choose
// is worse than asking.
func TestAutoSelectServer_SeveralServersAskRatherThanGuess(t *testing.T) {
	unsetQLEnvForTest(t)
	t.Setenv("XDG_RUNTIME_DIR", shortTempDir(t))
	pin := mustTestPin(t)
	path := writeTestConfig(t, `
schema = 1
[servers.aaa]
addr = "127.0.0.1:7443"
pin  = "`+pin+`"
[servers.bbb]
addr = "127.0.0.1:7444"
pin  = "`+pin+`"
`)

	err := runVerb([]string{"--config", path, "status", "--routes"})
	if exitCode(err) != 2 {
		t.Fatalf("an ambiguous fleet should be a usage error, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "name one") {
		t.Errorf("it should ask for a name, got: %v", err)
	}
	for _, want := range []string{"aaa", "bbb"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("it should list %q as available, got: %v", want, err)
		}
	}
}
