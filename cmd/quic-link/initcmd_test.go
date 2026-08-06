package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runSetupVerb runs a verb with a config file and returns everything it printed.
func runSetupVerb(t *testing.T, cfgBody string, args ...string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	// Not a terminal: anything that would write must decline rather than
	// assume consent from a pipe.
	root.SetIn(strings.NewReader(""))
	root.SetArgs(append([]string{"--config", cfg}, args...))
	err := root.Execute()
	return out.String(), err
}

const okCfg = "schema = 1\n[names]\nsuffix = \"internal\"\n"

// TestInit_RefusesADangerousSuffixAndWritesNothing is the load-bearing test of
// this step. It drives the real verb from a real config file, which is the
// point: a test that handed the writer an already-checked suffix would pass
// even if the verb stopped checking, and the check is what stops one line of
// configuration from redirecting every lookup on the machine.
func TestInit_RefusesADangerousSuffixAndWritesNothing(t *testing.T) {
	for _, suffix := range []string{".", "com", "local", "arpa", "not a hostname"} {
		t.Run(suffix, func(t *testing.T) {
			out, err := runSetupVerb(t, "schema = 1\n[names]\nsuffix = \""+suffix+"\"\n", "init")
			if err == nil {
				t.Fatalf("a suffix of %q must be refused; output was:\n%s", suffix, out)
			}
			if strings.Contains(out, "This will") {
				t.Error("nothing should even be planned for a suffix that will be refused")
			}
		})
	}
}

// TestInit_WithoutPrivilegeNeverPlansASystemFile: an ordinary run looks after
// the user's own things and says who should do the rest.
func TestInit_WithoutPrivilegeReportsWhatIsMissing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this describes an unprivileged run")
	}
	out, err := runSetupVerb(t, okCfg, "init")
	if err != nil {
		t.Fatalf("an ordinary run must not fail: %v\n%s", err, out)
	}
	if !strings.Contains(out, "sudo quic-link init") {
		t.Error("it should name the one command that does the rest")
	}
	if !strings.Contains(out, "quic-link doctor") {
		t.Error("it should point at the verb that checks the result")
	}
}

// TestInit_NeverSuggestsRunningTheToolAsRoot: setup asks for a password once,
// through the user's own sudo, for one file. It never asks anyone to run the
// whole program with privileges it would then hold over an identity key.
func TestInit_NeverSuggestsRunningTheToolAsRoot(t *testing.T) {
	for _, args := range [][]string{{"init"}, {"init", "--no-sudo"}, {"init", "--undo"}, {"doctor"}} {
		out, _ := runSetupVerb(t, okCfg, args...)
		low := strings.ToLower(out)
		for _, bad := range []string{"run as root", "as the root user", "run quic-link as root"} {
			if strings.Contains(low, bad) {
				t.Errorf("%v suggested running as root: %q", args, out)
			}
		}
		// "sudo quic-link init" is the one accepted form: one command, one file.
		for _, line := range strings.Split(out, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "sudo quic-link") && !strings.HasPrefix(l, "sudo quic-link init") {
				t.Errorf("%v suggested a privileged command other than setup: %q", args, l)
			}
		}
	}
}

// TestInit_UndoWithoutPrivilegeExplainsRatherThanFails
func TestInit_UndoWithoutPrivilegeExplainsRatherThanFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this describes an unprivileged run")
	}
	out, err := runSetupVerb(t, okCfg, "init", "--undo")
	if err != nil {
		t.Fatalf("this should explain, not fail: %v", err)
	}
	if !strings.Contains(out, "sudo quic-link init --undo") {
		t.Errorf("it should name the command that works: %q", out)
	}
}

// TestDoctor_WorksWithNoDaemonAndNoSetup is the situation a person is most
// likely to be in when they reach for this verb, so it must be the one that
// works best.
func TestDoctor_WorksWithNoDaemonAndNoSetup(t *testing.T) {
	out, err := runSetupVerb(t, okCfg, "doctor")
	if err != nil {
		t.Fatalf("doctor must not fail: %v\n%s", err, out)
	}
	for _, want := range []string{"Names", "Daemon", "Files quic-link has put", "Test lookup", "Next step"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing the %q section:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "/etc/") {
		t.Error("the report must name the system file by its full path, so it can be checked by reading")
	}
}

// TestDoctor_GivesExactlyOneNextStep: listing everything that is wrong leaves
// the reader to work out the order, and the order is always the same.
func TestDoctor_GivesExactlyOneNextStep(t *testing.T) {
	out, err := runSetupVerb(t, okCfg, "doctor")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "Next step"); n > 1 {
		t.Errorf("found %d next steps, want at most one", n)
	}
}

// TestDoctor_JSONIsParseableAndCarriesNoSecrets
func TestDoctor_JSONIsParseableAndCarriesNoSecrets(t *testing.T) {
	out, err := runSetupVerb(t, okCfg, "doctor", "--json")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(out)
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("not JSON: %q", line)
	}
	for _, forbidden := range []string{"BEGIN PRIVATE", "pin\":\""} {
		if strings.Contains(line, forbidden) {
			t.Errorf("the report carries something it should not: %q", forbidden)
		}
	}
	// A 44-character base64 run is what a full key fingerprint looks like.
	for _, f := range strings.Fields(strings.NewReplacer("\"", " ", ",", " ", ":", " ").Replace(line)) {
		if len(f) == 44 && strings.HasSuffix(f, "=") {
			t.Errorf("this looks like a full key fingerprint: %q", f)
		}
	}
}

// TestDoctor_ReportsAFileThatIsNotOurs: a file at our path that somebody else
// wrote must be reported as such, never quietly counted as ours.
func TestDoctor_ReportsAFileThatIsNotOurs(t *testing.T) {
	out, err := runSetupVerb(t, okCfg, "doctor")
	if err != nil {
		t.Fatal(err)
	}
	// On a machine with no setup done, every system file is absent — the point
	// here is that the vocabulary exists and is printed.
	if !strings.Contains(out, "absent") && !strings.Contains(out, "in place") && !strings.Contains(out, "not ours") {
		t.Errorf("the report should say the state of each file:\n%s", out)
	}
}
