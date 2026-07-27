package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/mauriciomem/quic-link/internal/config"
)

// sunPathLimit is the maximum unix socket path length in bytes on most OSes.
// macOS enforces 104 bytes; Linux allows 108. We use the more restrictive
// value to ensure the computed path works on both.
const sunPathLimit = 104

// socketPath resolves the daemon unix socket path according to the precedence
// defined in the config spec:
//
//  1. $XDG_RUNTIME_DIR/quic-link/daemon.sock (when $XDG_RUNTIME_DIR is set)
//  2. $TMPDIR/quic-link-<uid>/daemon.sock (when $TMPDIR is set and path fits)
//  3. /tmp/quic-link-<uid>/daemon.sock
//
// For each candidate the containing directory is created at mode 0700 and
// verified: symlinked directories are rejected, and the owner must be the
// effective uid. On any violation an error is returned that maps to exit 2
// (a usage/environment problem, not a transient network error).
//
// The socket file itself is chmod'd to 0600 by the daemon after binding
// (see daemon.Run). This is umask-independent.
func socketPath(_ *config.Config) (string, error) {
	uid := os.Getuid()
	uidStr := strconv.Itoa(uid)

	// Option 1: XDG_RUNTIME_DIR (Linux; per-user, mode-0700 tmpfs).
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		dir := filepath.Join(xdg, "quic-link")
		if err := ensureOwnedDir(dir, uid); err != nil {
			return "", err
		}
		return filepath.Join(dir, "daemon.sock"), nil
	}

	// Option 2: $TMPDIR per-user subdir (the common macOS path).
	// Only used when the full socket path fits under the sun_path limit;
	// macOS $TMPDIR is a long per-user path that can overflow the limit.
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		dir := filepath.Join(tmp, "quic-link-"+uidStr)
		p := filepath.Join(dir, "daemon.sock")
		if len(p) <= sunPathLimit {
			if err := ensureOwnedDir(dir, uid); err != nil {
				return "", err
			}
			return p, nil
		}
		// Path too long; fall through to the /tmp fallback.
	}

	// Option 3: /tmp per-user subdir (always short enough).
	dir := filepath.Join("/tmp", "quic-link-"+uidStr)
	if err := ensureOwnedDir(dir, uid); err != nil {
		return "", err
	}
	return filepath.Join(dir, "daemon.sock"), nil
}

// daemonSocketPath is the shared entry point for daemon and status verbs.
// cfg is unused today but threaded through so the signature is stable if a
// config key for the socket path is added later.
func daemonSocketPath(cfg *config.Config) (string, error) {
	return socketPath(cfg)
}

// ensureOwnedDir creates dir at mode 0700 if it does not exist, then verifies:
//
//   - The path is not a symlink (lstat check).
//   - The directory is owned by the given uid.
//   - The directory has no group-writable or world-writable bits set.
//
// These checks are load-bearing for the /tmp fallback path, which lives in a
// shared namespace where another user could pre-plant a directory or symlink at
// the target path. On XDG_RUNTIME_DIR the checks are a belt-and-suspenders
// guard in case the environment is misconfigured.
//
// On any violation the error wraps errUsage so main maps it to exit 2, giving
// the operator a clear message about the environmental problem to fix rather
// than an opaque failure.
func ensureOwnedDir(dir string, uid int) error {
	// Create with 0700; MkdirAll is a no-op if it exists.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory %s: %w: %w", dir, err, errUsage)
	}
	return verifyOwnedDir(dir, uid)
}

// verifyOwnedDir checks that dir is a real directory (not a symlink), is owned
// by uid, and has no group-writable or world-writable bits. It is exported as
// a helper so tests can call it directly without going through socketPath.
func verifyOwnedDir(dir string, uid int) error {
	// Lstat so we see the link itself, not its target.
	lst, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat socket directory %s: %w: %w", dir, err, errUsage)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket directory %s is a symlink; refusing to use it: %w", dir, errUsage)
	}
	if !lst.IsDir() {
		return fmt.Errorf("socket directory path %s exists but is not a directory: %w", dir, errUsage)
	}

	// Check ownership and mode via the underlying syscall stat.
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat socket directory %s: %w: %w", dir, err, errUsage)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Should never happen on supported platforms (Linux/macOS).
		return fmt.Errorf("socket directory %s: cannot read ownership information: %w", dir, errUsage)
	}
	if int(sys.Uid) != uid {
		return fmt.Errorf("socket directory %s is owned by uid %d, not the current uid %d; refusing: %w",
			dir, sys.Uid, uid, errUsage)
	}
	// Reject group-writable or world-writable bits (0o022 covers g+w and o+w).
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("socket directory %s has group/world-writable permissions (%04o); refusing: %w",
			dir, info.Mode().Perm(), errUsage)
	}
	return nil
}
