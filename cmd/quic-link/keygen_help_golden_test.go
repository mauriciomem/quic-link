package main

// @spec-handoff
// @interface newRootCmd() with args ["keygen", "--help"] -> help text on cmd.OutOrStdout()
// @behavior
//   - `quic-link keygen --help` output matches testdata/keygen_help.golden byte for byte
//   - the golden holds the pflag v1.1.0 rendering, where boolean flags read
//     `--force[=true|false]`; a pflag/cobra upgrade that changes flag rendering fails here
// @edge-cases
//   - HOME is pinned so the --out default (defaultKeyPath) is machine-independent
//   - output goes to an in-memory buffer: no TTY, no $COLUMNS (pflag does not wrap
//     flag usages; cobra templates do not read terminal width)
// @see ./keygen.go ./root.go
//
// Regenerating the golden after an intended rendering change: run
//   go test ./cmd/quic-link/ -run 'TestKeygenIdempotentAndForce/help_golden' -count=1 -v
// copy the "got" block from the failure into testdata/keygen_help.golden, and
// review the diff before committing.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// keygenHelpGolden is run as a subtest of TestKeygenIdempotentAndForce so the
// top-level result counts in scripts/expected-counts.txt stay unchanged.
func keygenHelpGolden(t *testing.T) {
	t.Setenv("HOME", "/home/golden")
	t.Setenv("COLUMNS", "")

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"keygen", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("keygen --help: %v", err)
	}

	want, err := os.ReadFile(filepath.Join("testdata", "keygen_help.golden"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got := out.String(); got != string(want) {
		t.Errorf("keygen --help drifted from testdata/keygen_help.golden\n--- want ---\n%s--- got ---\n%s", want, got)
	}
}
