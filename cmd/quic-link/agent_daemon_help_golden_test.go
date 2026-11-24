package main

// @spec-handoff
// @interface newRootCmd() with args ["agent", "--help"] and ["daemon", "--help"] -> help text on cmd.OutOrStdout()
// @behavior
//   - `quic-link agent --help` and `quic-link daemon --help` match testdata/agent_help.golden and
//     testdata/daemon_help.golden byte for byte; the goldens were captured from the release before
//     pairing work began, so a pairing flag, verb or option appearing in either help fails here
// @edge-cases
//   - HOME, XDG_RUNTIME_DIR and TMPDIR are pinned and QUIC_LINK_* cleared, so defaults derived from
//     them are machine-independent; output goes to an in-memory buffer (no TTY, no $COLUMNS)
//   - not parallel: it sets process environment
// @see ./agent.go ./daemoncmd.go ./keygen_help_golden_test.go
//
// This test guards an absence, so it passes from the start. Changing any one
// help string in agent.go or daemoncmd.go makes it fail (checked when it was
// added). Regenerate a golden only for an intended help change: run
//   go test ./cmd/quic-link/ -run 'TestAgentAndDaemonHelp_MatchBaseline' -count=1 -v
// copy the "got" block from the failure into the golden, and review the diff.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// renderHelp returns `quic-link <verb> --help` as a user would see it.
func renderHelp(t *testing.T, verb string) string {
	t.Helper()
	unsetQLEnvForTest(t)
	t.Setenv("HOME", "/home/golden")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", "")
	t.Setenv("COLUMNS", "")

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{verb, "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("%s --help: %v", verb, err)
	}
	return out.String()
}

func TestAgentAndDaemonHelp_MatchBaseline(t *testing.T) {
	for _, verb := range []string{"agent", "daemon"} {
		t.Run(verb, func(t *testing.T) {
			golden := filepath.Join("testdata", verb+"_help.golden")
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if len(want) == 0 {
				t.Fatalf("%s is empty: the comparison would be blind", golden)
			}
			if got := renderHelp(t, verb); got != string(want) {
				t.Errorf("%s --help drifted from %s\n--- want ---\n%s--- got ---\n%s", verb, golden, want, got)
			}
		})
	}
}
