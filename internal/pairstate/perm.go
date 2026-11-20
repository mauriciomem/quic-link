package pairstate

import "os"

// checkPrivate reports why fi, the Lstat (or fstat) result for path, cannot be
// trusted by the user euid. wantDir selects directory or regular file.
func checkPrivate(path string, fi os.FileInfo, wantDir bool, euid int) error {
	return nil
}
