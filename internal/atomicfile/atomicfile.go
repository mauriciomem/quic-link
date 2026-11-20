// Package atomicfile replaces files atomically and durably.
package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Write replaces path with data atomically and durably: a temp file in the
// same directory (0600 from CreateTemp, then chmod to mode) is written,
// fsynced, closed and renamed over path, then the parent directory is fsynced
// so the rename itself survives a crash. The parent is created 0700 if
// missing. On darwin (*os.File).Sync issues F_FULLFSYNC (the standard library
// falls back to fsync where that is unsupported), so no platform-specific
// code is needed for either sync.
//
// A directory fsync the filesystem does not support (EINVAL, ENOTSUP,
// EOPNOTSUPP from the sync call itself) is ignored: the new content is in
// place regardless. Any other error, including failing to open or close the
// directory, is returned. On any error before the rename the target is
// untouched; the temp file is removed on every failure.
func Write(path string, data []byte, mode os.FileMode) error {
	return writeWith(defaultOps(), path, data, mode)
}

// ops is the set of file operations writeWith performs on the temp file and
// its parent directory, injectable by same-package tests.
type ops struct {
	write    func(f *os.File, b []byte) error
	syncFile func(f *os.File) error
	close    func(f *os.File) error
	rename   func(oldpath, newpath string) error
	openDir  func(dir string) (*os.File, error)
	syncDir  func(d *os.File) error
	closeDir func(d *os.File) error
}

// defaultOps returns ops backed by the real os calls. It is a function, not a
// package variable, so tests can build their own ops without shared state.
func defaultOps() ops {
	return ops{
		write: func(f *os.File, b []byte) error {
			_, err := f.Write(b)
			return err
		},
		syncFile: (*os.File).Sync,
		close:    (*os.File).Close,
		rename:   os.Rename,
		openDir:  os.Open,
		syncDir:  (*os.File).Sync,
		closeDir: (*os.File).Close,
	}
}

// writeWith is Write with injectable file operations.
func writeWith(o ops, path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := tmp.Chmod(mode); err != nil {
		_ = o.close(tmp)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := o.write(tmp, data); err != nil {
		_ = o.close(tmp)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := o.syncFile(tmp); err != nil {
		_ = o.close(tmp)
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := o.close(tmp); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := o.rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return syncParent(o, dir)
}

// syncParent persists the rename by fsyncing dir. Only the sync call's
// "unsupported" errnos are ignored; the directory is closed even when the
// sync fails, and open/close failures are returned.
func syncParent(o ops, dir string) error {
	d, err := o.openDir(dir)
	if err != nil {
		return fmt.Errorf("open dir %s for sync: %w", dir, err)
	}
	syncErr := o.syncDir(d)
	closeErr := o.closeDir(d)
	if syncErr != nil && !syncUnsupported(syncErr) {
		return fmt.Errorf("sync dir %s: %w", dir, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close dir %s: %w", dir, closeErr)
	}
	return nil
}

// syncUnsupported reports whether err means the filesystem cannot fsync a
// directory (some network and FUSE filesystems).
func syncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}
