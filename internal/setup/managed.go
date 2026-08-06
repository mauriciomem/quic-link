// Package setup owns the files quic-link installs on the machine, and the
// checks that decide whether installing them will actually work.
//
// Every file written here carries a marker on its first line. The marker is
// what makes the difference between a file we may rewrite or remove and one
// that belongs to somebody else and happens to share a path — without it,
// "undo" would be indistinguishable from "delete a stranger's configuration".
package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Marker is the first line of every file quic-link writes. Both file formats
// this package produces treat a leading '#' as a comment, so it is inert.
//
// Removing it by hand is a supported way to take a file out of quic-link's
// hands: from then on the file is refused rather than rewritten or removed.
const Marker = "# Managed by quic-link. Remove this line to take ownership of this file."

var (
	// ErrNotOurs means a file exists at the path but was not written by us.
	ErrNotOurs = errors.New("setup: the file at that path was not written by quic-link")
	// ErrNotRegular means something that is not an ordinary file is in the way.
	ErrNotRegular = errors.New("setup: the path is not an ordinary file")
)

// Result says what a write did, so the caller can avoid acting on a no-op —
// restarting a system service that did not need restarting, for instance.
type Result int

const (
	// Unchanged means the file was already exactly right.
	Unchanged Result = iota
	// Created means there was nothing there before.
	Created
	// Updated means our own file was replaced with different content.
	Updated
)

// Managed reports whether content was written by quic-link.
func Managed(content []byte) bool {
	return bytes.HasPrefix(content, []byte(Marker))
}

// Body builds file content with the marker at the top.
func Body(lines ...string) []byte {
	return []byte(Marker + "\n" + strings.Join(lines, "\n") + "\n")
}

// Inspect reports what is currently at path.
func Inspect(path string) (exists, ours bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !fi.Mode().IsRegular() {
		// A symlink here would send a write somewhere we did not choose, and a
		// device or socket is not something to overwrite either.
		return true, false, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return true, false, err
	}
	return true, Managed(b), nil
}

// Write puts content at path, atomically, refusing anything already there that
// is not ours.
//
// The flags and the rename apply to different files, which is easy to get
// wrong: a rename target cannot be opened without following symlinks, and a
// destination opened exclusively could never be rewritten. So the temporary
// file is the one created exclusively and without following links, and the
// destination is checked with a stat and then replaced by a rename.
func Write(path string, content []byte, mode os.FileMode) (Result, error) {
	exists, ours, err := Inspect(path)
	if err != nil {
		return Unchanged, err
	}
	if exists && !ours {
		return Unchanged, fmt.Errorf("%w: %s", ErrNotOurs, path)
	}
	if exists {
		if b, err := os.ReadFile(path); err == nil && bytes.Equal(b, content) {
			return Unchanged, nil
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Unchanged, err
	}

	tmp, err := os.CreateTemp(dir, ".quic-link.tmp-*")
	if err != nil {
		return Unchanged, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename has happened

	// Set the mode explicitly. The mode passed to open is trimmed by the
	// umask, which on a stricter-than-usual account would leave a resolver
	// file the resolver cannot read.
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return Unchanged, err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return Unchanged, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Unchanged, err
	}
	if err := tmp.Close(); err != nil {
		return Unchanged, err
	}

	// Check once more immediately before replacing: the gap is small and the
	// directory is normally writable only by root, but the check costs nothing.
	if exists2, ours2, err := Inspect(path); err != nil {
		return Unchanged, err
	} else if exists2 && !ours2 {
		return Unchanged, fmt.Errorf("%w: %s", ErrNotOurs, path)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return Unchanged, err
	}
	// Without this the rename itself can be lost on power failure, leaving a
	// resolver pointed at a file that is not there.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}

	if exists {
		return Updated, nil
	}
	return Created, nil
}

// Remove deletes a file quic-link wrote, and refuses anything else.
func Remove(path string) (removed bool, err error) {
	exists, ours, err := Inspect(path)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if !ours {
		return false, fmt.Errorf("%w: %s", ErrNotOurs, path)
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return true, nil
}
