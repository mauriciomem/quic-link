package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// Note for anyone tidying this file: verifyOwnedDir is not private to the
// daemon socket. It is the one place that answers "is this directory really
// mine, and mine alone", and the naming layer will reuse it for any
// directory it keeps its own files in. Narrowing it to the socket's needs, or folding it
// into the socket-path code, would take that answer away from a second caller.

// TestVerifyOwnedDir_AcceptsGoodDir verifies that a normally-created temp
// directory with 0700 mode and the current uid passes the check.
func TestVerifyOwnedDir_AcceptsGoodDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := verifyOwnedDir(dir, os.Getuid()); err != nil {
		t.Errorf("verifyOwnedDir on a good dir: %v", err)
	}
}

// TestVerifyOwnedDir_RejectsSymlink verifies that a symlink at the dir path
// is rejected before binding, even if the symlink target is a valid directory.
// A symlink planted by another user in /tmp could redirect the socket path.
func TestVerifyOwnedDir_RejectsSymlink(t *testing.T) {
	target := t.TempDir()
	linkPath := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := verifyOwnedDir(linkPath, os.Getuid()); err == nil {
		t.Error("expected error for symlink dir, got nil")
	}
}

// TestVerifyOwnedDir_RejectsGroupWritable verifies that a directory with
// group-writable bits is rejected. The parent of the socket must not be
// writable by anyone except the owning uid.
func TestVerifyOwnedDir_RejectsGroupWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not meaningful on windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := verifyOwnedDir(dir, os.Getuid()); err == nil {
		t.Error("expected error for group-writable dir, got nil")
	}
}

// TestVerifyOwnedDir_RejectsWorldWritable verifies that a world-writable dir
// is rejected.
func TestVerifyOwnedDir_RejectsWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not meaningful on windows")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o707); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := verifyOwnedDir(dir, os.Getuid()); err == nil {
		t.Error("expected error for world-writable dir, got nil")
	}
}

// TestVerifyOwnedDir_RejectsWrongOwner verifies that verifyOwnedDir rejects a
// directory when passed a uid that does not match the actual owner. We pass
// uid+1 as the expected uid, which will mismatch the actual owner.
func TestVerifyOwnedDir_RejectsWrongOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; ownership mismatch cannot be simulated")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	wrongUID := os.Getuid() + 1
	if err := verifyOwnedDir(dir, wrongUID); err == nil {
		t.Errorf("expected error when checking dir with wrong uid %d, got nil", wrongUID)
	}
}

// TestSocketPath_ModeAfterBind verifies that socketPath creates the containing
// directory at 0700, and that after the socket is bound and chmod'd to 0600,
// the file mode is correct.
func TestSocketPath_ModeAfterBind(t *testing.T) {
	// Use /tmp directly as XDG_RUNTIME_DIR to keep the socket path short
	// (macOS t.TempDir() paths can exceed the 104-byte sun_path limit when
	// combined with the "quic-link/daemon.sock" suffix).
	xdgDir := fmt.Sprintf("/tmp/ql-socktest-%d", os.Getpid())
	if err := os.MkdirAll(xdgDir, 0o700); err != nil {
		t.Fatalf("mkdir xdg dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(xdgDir) })

	t.Setenv("XDG_RUNTIME_DIR", xdgDir)
	oldTmpdir := os.Getenv("TMPDIR")
	os.Unsetenv("TMPDIR")
	t.Cleanup(func() { os.Setenv("TMPDIR", oldTmpdir) })

	sock, err := socketPath(nil)
	if err != nil {
		t.Fatalf("socketPath: %v", err)
	}

	// Verify parent dir is 0700.
	dirInfo, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatalf("stat socket dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket dir mode = %04o, want 0700", perm)
	}

	// Bind a socket and chmod it to 0600 as daemon.Run does.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	t.Cleanup(func() { ln.Close(); os.Remove(sock) })

	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}
	sockInfo, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := sockInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket file mode = %04o, want 0600", perm)
	}
}

// TestSocketPath_SymlinkDirRejected verifies that when the socket's parent
// directory is a symlink, socketPath returns an error mapping to exit 2.
func TestSocketPath_SymlinkDirRejected(t *testing.T) {
	// Use short paths to stay under macOS sun_path limit.
	xdgBase := fmt.Sprintf("/tmp/ql-symlinktest-%d", os.Getpid())
	targetDir := xdgBase + "-target"
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.MkdirAll(xdgBase, 0o700); err != nil {
		t.Fatalf("mkdir xdg base: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(xdgBase)
		os.RemoveAll(targetDir)
	})

	// Place a symlink at the location socketPath would create the dir.
	linkPath := filepath.Join(xdgBase, "quic-link")
	if err := os.Symlink(targetDir, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	t.Setenv("XDG_RUNTIME_DIR", xdgBase)
	oldTmpdir := os.Getenv("TMPDIR")
	os.Unsetenv("TMPDIR")
	t.Cleanup(func() { os.Setenv("TMPDIR", oldTmpdir) })

	_, err := socketPath(nil)
	if err == nil {
		t.Fatal("expected error when socket dir is a symlink, got nil")
	}
	// The error should wrap errUsage so it maps to exit 2.
	if code := exitCodeForError(err); code != 2 {
		t.Errorf("error should map to exit 2, got %d: %v", code, err)
	}
}

// TestExitCodeMapping_Squatter verifies that an errSquatterType maps to exit 2.
func TestExitCodeMapping_Squatter(t *testing.T) {
	err := &errSquatterType{sock: "/tmp/test.sock", reason: "test"}
	if code := exitCodeForError(err); code != 2 {
		t.Errorf("errSquatterType should map to exit 2, got %d", code)
	}
}

// TestExitCodeMapping_OwnerRunning verifies the live-owner error still maps to exit 3.
func TestExitCodeMapping_OwnerRunning(t *testing.T) {
	err := &errOwnerRunningType{sock: "/tmp/test.sock"}
	if code := exitCodeForError(err); code != 3 {
		t.Errorf("errOwnerRunningType should map to exit 3, got %d", code)
	}
}

// TestSysStat_UidAccessible is a sanity check that os.Stat().Sys() returns
// a *syscall.Stat_t with a usable Uid field on this platform.
func TestSysStat_UidAccessible(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skipf("Stat_t not available on %s — peer-uid check uses a fallback", runtime.GOOS)
	}
	if sys.Uid != uint32(os.Getuid()) {
		t.Errorf("Stat_t.Uid = %d, want %d", sys.Uid, os.Getuid())
	}
}
