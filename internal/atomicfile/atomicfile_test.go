/**
 * @spec-handoff
 * @interface Write(path string, data []byte, mode os.FileMode) error
 * @interface writeWith(o ops, path string, data []byte, mode os.FileMode) error  // ops{write, syncFile, close, rename, openDir, syncDir, closeDir}
 * @behavior
 *   - Order on success: MkdirAll(parent, 0700) -> CreateTemp(".tmp-*") -> Chmod(mode) -> write -> syncFile -> close -> rename -> openDir(parent) -> syncDir -> closeDir
 *   - Target ends with the new content and exactly the requested mode; a created parent dir is 0700; no ".tmp-*" left
 *   - write/syncFile/close/rename failure: error wraps the cause (errors.Is), the target is untouched, the temp file is removed;
 *     a failed write or syncFile still closes the temp file; nothing after the failed op runs
 *   - syncDir failure after rename: error wraps the cause; the new content is already in place; closeDir still runs
 * @edge-cases
 *   - EINVAL, ENOTSUP, EOPNOTSUPP from syncDir ONLY -> nil (filesystem cannot sync directories); EIO from syncDir -> returned
 *   - the same errnos from openDir or closeDir -> returned (wrapped), never ignored; a closeDir failure after an ignored syncDir errno -> returned
 * @see ./atomicfile.go
 */

package atomicfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

var errInjected = errors.New("injected failure")

// recorder builds ops that append each op name to calls. File writes,
// closes, renames and the directory open/close are real; both syncs are
// stubbed (recorded, return nil) so the order is observed without depending on
// what the test filesystem does with fsync.
type recorder struct {
	calls   []string
	openDir []string   // directories passed to openDir
	opened  []*os.File // handles openDir returned
	synced  []*os.File // handles syncDir received
	closed  []*os.File // handles closeDir received
}

func (r *recorder) ops() ops {
	return ops{
		write: func(f *os.File, b []byte) error {
			r.calls = append(r.calls, "write")
			_, err := f.Write(b)
			return err
		},
		syncFile: func(*os.File) error {
			r.calls = append(r.calls, "syncFile")
			return nil
		},
		close: func(f *os.File) error {
			r.calls = append(r.calls, "close")
			return f.Close()
		},
		rename: func(o, n string) error {
			r.calls = append(r.calls, "rename")
			return os.Rename(o, n)
		},
		openDir: func(dir string) (*os.File, error) {
			r.calls = append(r.calls, "openDir")
			r.openDir = append(r.openDir, dir)
			d, err := os.Open(dir)
			if err == nil {
				r.opened = append(r.opened, d)
			}
			return d, err
		},
		syncDir: func(d *os.File) error {
			r.calls = append(r.calls, "syncDir")
			r.synced = append(r.synced, d)
			return nil
		},
		closeDir: func(d *os.File) error {
			r.calls = append(r.calls, "closeDir")
			r.closed = append(r.closed, d)
			return d.Close()
		},
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("temp files left behind: %v", m)
	}
}

func assertFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("target content = %q, want %q", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != mode {
		t.Errorf("target mode = %o, want %o", fi.Mode().Perm(), mode)
	}
}

func assertDirMode(t *testing.T, dir string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != want {
		t.Errorf("dir %s mode = %o, want %o", dir, fi.Mode().Perm(), want)
	}
}

// existingTarget creates dir/target with "old" at 0600 and returns its path.
func existingTarget(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "target")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func TestWrite_CreatesFileWithModeAndPrivateParent(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o600, 0o640} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "a", "b")
			path := filepath.Join(dir, "file")
			if err := Write(path, []byte("data"), mode); err != nil {
				t.Fatalf("Write: %v", err)
			}
			assertFile(t, path, []byte("data"), mode)
			assertDirMode(t, dir, 0o700)
			assertDirMode(t, filepath.Dir(dir), 0o700)
			assertNoTempFiles(t, dir)
		})
	}
}

func TestWrite_ReplacesExistingContentAndMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("old content, longer than the new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertFile(t, path, []byte("new"), 0o600)
	assertNoTempFiles(t, dir)
}

func TestWrite_SyncsInDurableOrder(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(dir, "id.key")
	var r recorder

	if err := writeWith(r.ops(), path, []byte("new"), 0o600); err != nil {
		t.Fatalf("writeWith: %v", err)
	}
	want := []string{"write", "syncFile", "close", "rename", "openDir", "syncDir", "closeDir"}
	if !slices.Equal(r.calls, want) {
		t.Errorf("op order = %v, want %v", r.calls, want)
	}
	if !slices.Equal(r.openDir, []string{dir}) {
		t.Errorf("openDir dirs = %v, want [%s]", r.openDir, dir)
	}
	if len(r.opened) != 1 || len(r.synced) != 1 || len(r.closed) != 1 ||
		r.synced[0] != r.opened[0] || r.closed[0] != r.opened[0] {
		t.Errorf("syncDir/closeDir must receive the handle openDir returned: opened=%v synced=%v closed=%v",
			r.opened, r.synced, r.closed)
	}
	assertFile(t, path, []byte("new"), 0o600)
	assertDirMode(t, dir, 0o700)
	assertNoTempFiles(t, dir)
}

func TestWrite_FileSyncFailureLeavesTargetUntouched(t *testing.T) {
	t.Parallel()
	dir, path := existingTarget(t)
	var r recorder
	o := r.ops()
	o.syncFile = func(*os.File) error {
		r.calls = append(r.calls, "syncFile")
		return errInjected
	}

	err := writeWith(o, path, []byte("new"), 0o600)
	if !errors.Is(err, errInjected) {
		t.Errorf("err = %v, want wrapping %v", err, errInjected)
	}
	if want := []string{"write", "syncFile", "close"}; !slices.Equal(r.calls, want) {
		t.Errorf("ops = %v, want %v (temp closed, no rename)", r.calls, want)
	}
	assertFile(t, path, []byte("old"), 0o600)
	assertNoTempFiles(t, dir)
}

func TestWrite_WriteFailureLeavesTargetUntouched(t *testing.T) {
	t.Parallel()
	dir, path := existingTarget(t)
	var r recorder
	o := r.ops()
	o.write = func(*os.File, []byte) error {
		r.calls = append(r.calls, "write")
		return errInjected
	}

	err := writeWith(o, path, []byte("new"), 0o600)
	if !errors.Is(err, errInjected) {
		t.Errorf("err = %v, want wrapping %v", err, errInjected)
	}
	if want := []string{"write", "close"}; !slices.Equal(r.calls, want) {
		t.Errorf("ops = %v, want %v (temp closed, no sync, no rename)", r.calls, want)
	}
	assertFile(t, path, []byte("old"), 0o600)
	assertNoTempFiles(t, dir)
}

func TestWrite_CloseFailureLeavesTargetUntouched(t *testing.T) {
	t.Parallel()
	dir, path := existingTarget(t)
	var r recorder
	o := r.ops()
	o.close = func(f *os.File) error {
		r.calls = append(r.calls, "close")
		_ = f.Close() // release the descriptor; report failure anyway
		return errInjected
	}

	err := writeWith(o, path, []byte("new"), 0o600)
	if !errors.Is(err, errInjected) {
		t.Errorf("err = %v, want wrapping %v", err, errInjected)
	}
	if slices.Contains(r.calls, "rename") {
		t.Errorf("rename called after close failure; ops = %v", r.calls)
	}
	assertFile(t, path, []byte("old"), 0o600)
	assertNoTempFiles(t, dir)
}

func TestWrite_RenameFailureRemovesTemp(t *testing.T) {
	t.Parallel()
	dir, path := existingTarget(t)
	var r recorder
	o := r.ops()
	o.rename = func(string, string) error {
		r.calls = append(r.calls, "rename")
		return errInjected
	}

	err := writeWith(o, path, []byte("new"), 0o600)
	if !errors.Is(err, errInjected) {
		t.Errorf("err = %v, want wrapping %v", err, errInjected)
	}
	if want := []string{"write", "syncFile", "close", "rename"}; !slices.Equal(r.calls, want) {
		t.Errorf("ops = %v, want %v (no directory sync after a failed rename)", r.calls, want)
	}
	assertFile(t, path, []byte("old"), 0o600)
	assertNoTempFiles(t, dir)
}

func TestWrite_DirSyncFailureReturnsError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{"injected", errInjected},
		{"EIO", syscall.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, path := existingTarget(t)
			var r recorder
			o := r.ops()
			o.syncDir = func(*os.File) error {
				r.calls = append(r.calls, "syncDir")
				return tc.cause
			}

			err := writeWith(o, path, []byte("new"), 0o600)
			if !errors.Is(err, tc.cause) {
				t.Errorf("err = %v, want wrapping %v", err, tc.cause)
			}
			if !slices.Contains(r.calls, "closeDir") {
				t.Errorf("closeDir not called after syncDir failure (descriptor leak); ops = %v", r.calls)
			}
			assertFile(t, path, []byte("new"), 0o600)
			assertNoTempFiles(t, dir)
		})
	}
}

// unsupported are the errnos a filesystem that cannot sync a directory
// reports. On Linux EOPNOTSUPP and ENOTSUP are the same value, so the
// EOPNOTSUPP row only discriminates on darwin, where the two differ; the
// errnos are injected through ops, so this table passes or fails the same
// way on both.
var unsupported = []struct {
	name  string
	errno syscall.Errno
}{
	{"EINVAL", syscall.EINVAL},
	{"ENOTSUP", syscall.ENOTSUP},
	{"EOPNOTSUPP", syscall.EOPNOTSUPP},
}

func TestWrite_DirSyncUnsupportedIsIgnored(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cause   error
		wantErr bool
	}{
		{"control_EIO_still_returned", syscall.EIO, true},
	}
	for _, u := range unsupported {
		cases = append(cases, struct {
			name    string
			cause   error
			wantErr bool
		}{u.name, u.errno, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, path := existingTarget(t)
			var r recorder
			o := r.ops()
			o.syncDir = func(*os.File) error {
				r.calls = append(r.calls, "syncDir")
				return tc.cause
			}

			err := writeWith(o, path, []byte("new"), 0o600)
			if !slices.Contains(r.calls, "syncDir") {
				t.Errorf("syncDir not called; ops = %v", r.calls)
			}
			if !slices.Contains(r.calls, "closeDir") {
				t.Errorf("closeDir not called after syncDir error; ops = %v", r.calls)
			}
			if tc.wantErr {
				if !errors.Is(err, tc.cause) {
					t.Errorf("err = %v, want wrapping %v", err, tc.cause)
				}
			} else if err != nil {
				t.Errorf("err = %v, want nil for an unsupported directory sync", err)
			}
			assertFile(t, path, []byte("new"), 0o600)
			assertNoTempFiles(t, dir)
		})
	}
}

// The "unsupported" filter belongs to the directory Sync call alone. The same
// errnos from opening or closing the directory are real failures.
func TestWrite_DirOpenAndCloseErrorsAreNotIgnored(t *testing.T) {
	t.Parallel()
	for _, u := range unsupported {
		t.Run("openDir_"+u.name, func(t *testing.T) {
			t.Parallel()
			_, path := existingTarget(t)
			var r recorder
			o := r.ops()
			o.openDir = func(string) (*os.File, error) {
				r.calls = append(r.calls, "openDir")
				return nil, &os.PathError{Op: "open", Path: "dir", Err: u.errno}
			}

			err := writeWith(o, path, []byte("new"), 0o600)
			if !errors.Is(err, u.errno) {
				t.Errorf("err = %v, want an error wrapping %v from openDir", err, u.errno)
			}
			if slices.Contains(r.calls, "syncDir") {
				t.Errorf("syncDir called without an open directory; ops = %v", r.calls)
			}
		})
		t.Run("closeDir_"+u.name, func(t *testing.T) {
			t.Parallel()
			_, path := existingTarget(t)
			var r recorder
			o := r.ops()
			o.closeDir = func(d *os.File) error {
				r.calls = append(r.calls, "closeDir")
				_ = d.Close() // release the descriptor; report failure anyway
				return &os.PathError{Op: "close", Path: "dir", Err: u.errno}
			}

			err := writeWith(o, path, []byte("new"), 0o600)
			if !errors.Is(err, u.errno) {
				t.Errorf("err = %v, want an error wrapping %v from closeDir", err, u.errno)
			}
			if !slices.Contains(r.calls, "syncDir") {
				t.Errorf("syncDir not called; ops = %v", r.calls)
			}
		})
		// An ignored "unsupported" sync must not hide a close failure after it.
		t.Run("syncUnsupportedThenClose_"+u.name, func(t *testing.T) {
			t.Parallel()
			_, path := existingTarget(t)
			var r recorder
			o := r.ops()
			o.syncDir = func(*os.File) error {
				r.calls = append(r.calls, "syncDir")
				return u.errno
			}
			o.closeDir = func(d *os.File) error {
				r.calls = append(r.calls, "closeDir")
				_ = d.Close()
				return errInjected
			}

			err := writeWith(o, path, []byte("new"), 0o600)
			if !errors.Is(err, errInjected) {
				t.Errorf("err = %v, want an error wrapping %v from closeDir after an unsupported sync", err, errInjected)
			}
			if !slices.Contains(r.calls, "closeDir") {
				t.Errorf("closeDir not called; ops = %v", r.calls)
			}
		})
	}
}
