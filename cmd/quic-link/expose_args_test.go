package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestExposeCmd_EveryWrongInvocationIsAUsageError covers the exit code a script
// sees, which is part of what this program promises and not merely a detail of
// how the error was produced.
//
// The count of positional arguments is checked by the command framework before
// this program's own code runs, and that check's error takes a different route
// out than every other refusal — one that lands on the generic exit code rather
// than the one usage errors are supposed to use. Wrapping the check is what
// puts it back on the same path; this is what notices if the wrapping is
// dropped.
func TestExposeCmd_EveryWrongInvocationIsAUsageError(t *testing.T) {
	cases := map[string][]string{
		"no arguments at all": {},
		"three arguments":     {"server1", "3000", "extra"},
		"four arguments":      {"a", "b", "c", "d"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			cmd := newExposeCmd(&app{})
			err := cmd.Args(cmd, args)
			if err == nil {
				t.Fatalf("%v was accepted", args)
			}
			if got := exitCodeForError(err); got != 2 {
				t.Errorf("%v exits %d, want 2 — a wrong number of arguments is a usage error "+
					"like every other way of invoking this verb wrongly", args, got)
			}
		})
	}

	// The shapes that must still be accepted, so the check above cannot pass by
	// refusing everything.
	for _, args := range [][]string{{"3000"}, {"server1", "3000"}} {
		cmd := newExposeCmd(&app{})
		if err := cmd.Args(cmd, args); err != nil {
			t.Errorf("%v was refused: %v", args, err)
		}
	}
}

var _ = cobra.RangeArgs
