package tunnel

import (
	"regexp"
	"testing"
)

// TestNewReqID verifies that every call produces a 16-character lowercase hex
// string and that two consecutive calls produce different values.
func TestNewReqID(t *testing.T) {
	hexPattern := regexp.MustCompile(`^[0-9a-f]{16}$`)

	a := NewReqID()
	if !hexPattern.MatchString(a) {
		t.Fatalf("NewReqID() = %q, want 16 lowercase hex chars", a)
	}

	b := NewReqID()
	if !hexPattern.MatchString(b) {
		t.Fatalf("NewReqID() = %q, want 16 lowercase hex chars", b)
	}

	if a == b {
		t.Errorf("two consecutive NewReqID() calls returned the same value %q", a)
	}
}
