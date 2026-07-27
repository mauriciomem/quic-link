// Package ipc — white-box tests for the errno classifier helpers.
// These are in package ipc (not ipc_test) to access the unexported functions.
package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestIsNetRefused_DanglingSocket verifies that isNetRefused correctly
// identifies ECONNREFUSED from a dangling unix socket dial (file exists, no
// listener). This is the exact error path the single-instance probe encounters
// when the daemon crashed without removing its socket file.
//
// Before the fix, isNetRefused used string-matching ("connection refused") and
// failed on darwin where the wrapped error message is "connect: connection
// refused". The errno-based fix (errors.Is(err, syscall.ECONNREFUSED)) unwraps
// the chain correctly on both Linux and macOS.
func TestIsNetRefused_DanglingSocket(t *testing.T) {
	// Use a short path that fits under the macOS 104-byte sun_path limit.
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	// Shorten further if the TempDir path is already long.
	if len(sock) > 100 {
		sock = os.TempDir() + "/ql-isnetref-test.sock"
		t.Cleanup(func() { os.Remove(sock) })
	}

	// Bind a listener to create the socket file.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	// Close the listener without removing the socket file so we simulate a
	// dangling socket: the file exists, but nothing is listening on it.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	ln.Close()

	if _, statErr := os.Stat(sock); os.IsNotExist(statErr) {
		// Some platforms unlink on close regardless of SetUnlinkOnClose.
		t.Skip("socket file was removed on close; cannot simulate dangling socket on this platform")
	}

	// Dial the dangling socket — should get ECONNREFUSED.
	_, dialErr := net.Dial("unix", sock)
	if dialErr == nil {
		t.Fatal("expected dial error for dangling socket, got nil")
	}

	// isNetRefused must return true for this exact error.
	if !isNetRefused(dialErr) {
		t.Errorf("isNetRefused(%T: %v) = false, want true for ECONNREFUSED from dangling socket", dialErr, dialErr)
	}
}

// TestIsNetRefused_NoSuchFile verifies that isNetRefused returns false when the
// socket path does not exist at all (ENOENT, not ECONNREFUSED).
func TestIsNetRefused_NoSuchFile(t *testing.T) {
	_, dialErr := net.Dial("unix", "/tmp/ql-nonexistent-path-xyz-12345.sock")
	if dialErr == nil {
		t.Skip("unexpectedly connected to a non-existent socket")
	}
	if isNetRefused(dialErr) {
		t.Errorf("isNetRefused should be false for ENOENT (no such file), got true; err = %v", dialErr)
	}
}
