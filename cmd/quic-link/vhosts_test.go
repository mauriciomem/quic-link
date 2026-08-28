package main

// @spec-handoff
//
// vhosts is the only verb in this CLI with an Args validator that skips
// wrapArgs (util.go states the rule outright: every command that sets one
// must wrap it). A bad argument count therefore falls through
// exitCodeForError's default case and exits 1 instead of the documented 2
// ("bad usage") — at both the parent "vhosts" command (MaximumNArgs(1)) and
// the "vhosts rm" subcommand (RangeArgs(1, 2)).
//
// Interface: cobra's own Args validation failure, reached with no server
// resolution and no daemon involved at all — these two tests exercise pure
// argument-count checking.
//
// Behaviors covered:
//   - "vhosts" given two positional arguments (its Use string takes at
//     most one) exits 2, not 1.
//   - "vhosts rm" given zero, or given three, positional arguments (its Use
//     string takes one or two) exits 2, not 1.
//
// Edge cases: this is deliberately not routed through any daemon or config
// fixture — a bad argument count is rejected by cobra before RunE runs, so
// no server needs to exist for these to be meaningful.

import (
	"testing"
)

// TestVhosts_TooManyArgs_Exit2_NotExit1 pins the parent command's wrapArgs
// gap: cobra.MaximumNArgs(1), unwrapped, reports a bad count as a bare
// cobra error, which exitCodeForError's default case maps to 1.
func TestVhosts_TooManyArgs_Exit2_NotExit1(t *testing.T) {
	unsetQLEnvForTest(t)
	err := runVerb([]string{"vhosts", "a", "b"})
	if err == nil {
		t.Fatal("expected an error for too many arguments")
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exitCode = %d, want 2 (bad usage), err=%v", got, err)
	}
}

// TestVhostsRm_TooManyArgs_Exit2_NotExit1 pins the "rm" subcommand's
// wrapArgs gap: cobra.RangeArgs(1, 2), unwrapped, exits 1 for a count
// outside that range instead of the documented 2.
func TestVhostsRm_TooManyArgs_Exit2_NotExit1(t *testing.T) {
	unsetQLEnvForTest(t)
	err := runVerb([]string{"vhosts", "rm", "a", "b", "c"})
	if err == nil {
		t.Fatal("expected an error for too many arguments")
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exitCode = %d, want 2 (bad usage), err=%v", got, err)
	}
}

// TestVhostsRm_NoArgs_Exit2_NotExit1 covers the other edge of the same
// range validator: zero arguments, below the required minimum of one.
func TestVhostsRm_NoArgs_Exit2_NotExit1(t *testing.T) {
	unsetQLEnvForTest(t)
	err := runVerb([]string{"vhosts", "rm"})
	if err == nil {
		t.Fatal("expected an error for a missing NAME argument")
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exitCode = %d, want 2 (bad usage), err=%v", got, err)
	}
}
