//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd

package daemon

// coredump_other_test.go tests disableCoreDump on platforms where it is a
// no-op (Windows, Plan 9, etc.). On these platforms the function returns a
// non-nil error reporting that the feature is not supported; daemon.Run logs
// this at Warn level and continues rather than aborting startup.

import "testing"

// TestDisableCoreDump_NoOp verifies that on unsupported platforms
// disableCoreDump returns a non-nil error (not silently succeeds), so the
// daemon correctly identifies the missing protection and warns the operator.
func TestDisableCoreDump_NoOp(t *testing.T) {
	// NOT parallel — consistent with the Unix variant; this mutation is
	// process-wide on all platforms, even when it is a no-op.
	err := disableCoreDump()
	if err == nil {
		t.Error("disableCoreDump() on an unsupported platform should return a non-nil error, got nil")
	}
}
