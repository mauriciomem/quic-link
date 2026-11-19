// Package atomicfile replaces files atomically and durably.
package atomicfile

import (
	"errors"
	"os"
)

// errNotImplemented is a placeholder until Write is implemented.
var errNotImplemented = errors.New("atomicfile: not implemented")

// Write replaces path with data atomically and durably. Placeholder: not
// implemented yet.
func Write(path string, data []byte, mode os.FileMode) error {
	return writeWith(ops{}, path, data, mode)
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

// writeWith is Write with injectable file operations. Placeholder: not
// implemented yet.
func writeWith(_ ops, _ string, _ []byte, _ os.FileMode) error {
	return errNotImplemented
}
