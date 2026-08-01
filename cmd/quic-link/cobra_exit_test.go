package main

import "testing"

// TestCobraErrorsExitTwo drives executeRoot end-to-end (not exitCodeForError in
// isolation) for the three cobra-owned error paths that bypass every
// hand-written usageErrorf call site: an unknown flag, a malformed flag value,
// and a wrong positional-argument count. The CLI contract says all usage
// errors exit 2; cobra's own ParseFlags/ValidateArgs errors are plain errors
// with no relation to errUsage, so before the fix they fell through
// exitCodeForError's default case and exited 1.
func TestCobraErrorsExitTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"status", "--this-flag-does-not-exist"}},
		{"malformed flag value", []string{"status", "--json=not-a-bool"}},
		{"wrong arg count (too few)", []string{"stdio", "server1"}},
		{"wrong arg count (too many)", []string{"status", "extra-arg"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runVerb(tc.args)
			if err == nil {
				t.Fatalf("expected an error for args %v, got nil", tc.args)
			}
			if got := exitCode(err); got != 2 {
				t.Errorf("exitCode(%v) = %d, want 2 (usage error): %v", tc.args, got, err)
			}
		})
	}
}
