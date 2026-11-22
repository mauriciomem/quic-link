package pairstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkPrivate reports why fi, the Lstat (or fstat) result for path, cannot be
// trusted by the user euid. wantDir selects directory or regular file.
//
// It judges fi alone and never stats path again, so the answer is about the
// object that was actually looked at. It mirrors the socket directory check
// in cmd/quic-link, which this package cannot import.
func checkPrivate(path string, fi os.FileInfo, wantDir bool, euid int) error {
	mode := fi.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		return unsafePath(path, "is a symbolic link")
	case wantDir && !mode.IsDir():
		return unsafePath(path, "is not a directory")
	case !wantDir && !mode.IsRegular():
		return unsafePath(path, "is not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return unsafePath(path, "has no ownership information")
	}
	if int(st.Uid) != euid {
		return unsafePath(path, fmt.Sprintf("is owned by uid %d, not %d", st.Uid, euid))
	}
	if perm := mode.Perm(); perm&0o022 != 0 {
		return unsafePath(path, fmt.Sprintf("is writable by group or others (mode %04o)", perm))
	}
	return nil
}

func unsafePath(path, problem string) error {
	return fmt.Errorf("%w: %s %s", ErrUnsafePath, path, problem)
}

// verifyStateDir Lstats dir and applies checkPrivate(..., true, os.Geteuid()).
// It returns (false, nil) when dir does not exist.
func verifyStateDir(dir string) (exists bool, err error) {
	return verifyState(dir, true)
}

// verifyStateFile is verifyStateDir for a state file (wantDir false).
func verifyStateFile(path string) (exists bool, err error) {
	return verifyState(path, false)
}

func verifyState(path string, wantDir bool) (bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pairstate: stat %s: %w", path, err)
	}
	if err := checkPrivate(path, fi, wantDir, os.Geteuid()); err != nil {
		return false, err
	}
	return true, nil
}

// verifyStatePath checks the directory of path, then path itself. exists is
// false when either is missing, so the caller treats the state as empty.
func verifyStatePath(path string) (exists bool, err error) {
	if ok, err := verifyStateDir(filepath.Dir(path)); !ok || err != nil {
		return false, err
	}
	return verifyStateFile(path)
}

// readStateFile opens and reads one state file. Stub: not implemented yet.
func readStateFile(path string) ([]byte, error) { return os.ReadFile(path) }
