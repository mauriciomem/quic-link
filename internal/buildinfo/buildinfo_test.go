package buildinfo

import "testing"

// TestDefaults verifies that an un-stamped build (no -ldflags -X overrides)
// reports the documented placeholder values rather than an empty string,
// which would be a confusing "version: " line for an operator who forgot
// -ldflags.
func TestDefaults(t *testing.T) {
	if got := Version(); got != "dev" {
		t.Errorf("Version() = %q, want %q (default placeholder)", got, "dev")
	}
	if got := Commit(); got != "none" {
		t.Errorf("Commit() = %q, want %q (default placeholder)", got, "none")
	}
}
