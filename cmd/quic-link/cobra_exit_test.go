package main

import (
	"context"
	"path/filepath"
	"testing"
)

// TestCobraErrorsExitTwo drives executeRoot end-to-end (not exitCodeForError in
// isolation) for the cobra-owned error paths that bypass every hand-written
// usageErrorf call site: an unknown flag, a malformed flag value, and a wrong
// positional-argument count. The CLI contract says all usage errors exit 2;
// cobra's own ParseFlags/ValidateArgs errors are plain errors with no relation
// to errUsage, so before the fix they fell through exitCodeForError's default
// case and exited 1.
//
// doctor, init, keygen, and agent take no positional arguments and are
// exercised here for exactly that reason: none of the four set an Args
// validator, so today a stray one is accepted and ignored rather than
// rejected, and none of the four appear in status_routes_test.go's or any
// other file's coverage of this contract. Each needs just enough setup to
// reach argument validation without touching anything real on the machine
// running the test: a temporary HOME keeps doctor's and init's file survey
// off the developer's own account, keygen is pointed at a path inside that
// same temporary HOME so nothing is written outside it if the fix is somehow
// bypassed, and agent's context is already cancelled before the call so a
// binding attempt racing ahead of Args validation cannot hold a real port.
// cobra runs Args validation before RunE, so a correctly wrapped validator
// never reaches any of that in the first place — these safeguards exist for
// the pre-fix code this test is red against, not for the fixed code it is
// meant to pass against.
func TestCobraErrorsExitTwo(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	pin := mustTestPin(t)
	keyPath := filepath.Join(tmp, "probe-key.pem")

	cases := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"status", "--this-flag-does-not-exist"}},
		{"malformed flag value", []string{"status", "--json=not-a-bool"}},
		{"wrong arg count (too few)", []string{"stdio", "server1"}},
		{"wrong arg count (too many)", []string{"status", "extra-arg"}},
		{"doctor takes no arguments", []string{"doctor", "extra-arg"}},
		{"init takes no arguments", []string{"init", "extra-arg"}},
		{"keygen takes no arguments", []string{"keygen", "--out", keyPath, "extra-arg"}},
		{"agent takes no arguments", []string{
			"agent", "--listen", "127.0.0.1:0", "--key", keyPath,
			"--authorized-client", pin, "extra-arg",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // never let a correctly rejected call reach agent's bind
			err := runVerbCtx(ctx, tc.args)
			if err == nil {
				t.Fatalf("expected an error for args %v, got nil", tc.args)
			}
			if got := exitCode(err); got != 2 {
				t.Errorf("exitCode(%v) = %d, want 2 (usage error): %v", tc.args, got, err)
			}
		})
	}
}
