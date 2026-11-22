package pairstate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkPrivate reports why fi, the Lstat (or fstat) result for path, cannot be
// trusted by the user euid. wantDir selects directory or regular file.
//
// It judges fi alone and never stats path again, so the answer is about the
// object that was actually looked at. It mirrors the socket directory check
// in cmd/quic-link, which this package cannot import.
func checkPrivate(path string, fi os.FileInfo, wantDir bool, euid int) error {
	if err := checkOwned(path, fi, wantDir, euid); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return unsafePath(path, fmt.Sprintf("is writable by group or others (mode %04o)", perm))
	}
	return nil
}

// checkLock is checkPrivate for a lock file, which must also not be readable
// by group or others: flock succeeds on a read-only descriptor, so another
// user able to open the lock could hold it and block every writer.
func checkLock(path string, fi os.FileInfo, euid int) error {
	if err := checkOwned(path, fi, false, euid); err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return unsafePath(path, fmt.Sprintf("is readable or writable by group or others (mode %04o); "+
			"chmod 600 it, or delete it if another user may already hold it open", perm))
	}
	return nil
}

// checkOwned is the type and ownership part of checkPrivate.
func checkOwned(path string, fi os.FileInfo, wantDir bool, euid int) error {
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

// checkStatePathSyntax refuses a path that is not absolute and clean, before
// anything touches the file system: the directory checks look at
// filepath.Dir(path), which for a relative or unclean path need not be the
// directory the file is actually opened in.
func checkStatePathSyntax(path string) error {
	if !filepath.IsAbs(path) {
		return unsafePath(fmt.Sprintf("%+q", path), "is not an absolute path")
	}
	if filepath.Clean(path) != path {
		return unsafePath(fmt.Sprintf("%+q", path), fmt.Sprintf("is not a clean path (want %+q)", filepath.Clean(path)))
	}
	return nil
}

// maxStateFile is the largest state file a reader accepts.
const maxStateFile = 1 << 20

// readStateFile opens path without following a symbolic link and without
// blocking on a FIFO, checks on the open descriptor that it is a private
// regular file (see checkPrivate), and reads at most maxStateFile bytes. It
// re-checks what it opened, so a file swapped in after an earlier Lstat is
// refused too. A missing file is an error matching fs.ErrNotExist; a larger
// file is a *MalformedError with Line 0.
func readStateFile(path string) (data []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, unsafePath(path, "is a symbolic link")
	case errors.Is(err, fs.ErrNotExist):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("pairstate: open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			data, err = nil, fmt.Errorf("pairstate: close %s: %w", path, cerr)
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("pairstate: stat %s: %w", path, err)
	}
	if err := checkPrivate(path, fi, false, os.Geteuid()); err != nil {
		return nil, err
	}
	data, err = io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return nil, fmt.Errorf("pairstate: read %s: %w", path, err)
	}
	if len(data) > maxStateFile {
		return nil, &MalformedError{Path: path, Reason: "file larger than 1 MiB"}
	}
	return data, nil
}
