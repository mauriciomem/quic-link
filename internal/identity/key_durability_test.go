/**
 * @spec-handoff
 * @interface writeFileAtomicWith(ops fsOps, path string, data []byte, mode os.FileMode) error
 * @behavior
 *   - Operation order on success: write -> syncFile -> close -> rename -> syncDir(parent dir)
 *   - Target ends with the new content and the requested mode; a created parent dir is 0700
 *   - syncFile failure: error wraps the cause (errors.Is), rename is never called,
 *     an existing target is unchanged, no ".tmp-*" file is left behind
 *   - syncDir failure after rename: error wraps the cause; new content is already in place
 * @edge-cases
 *   - syncDir returning EINVAL or ENOTSUP (filesystem cannot sync directories) -> nil error
 *   - any other syncDir error (e.g. EIO) is still returned
 * @see ./key.go
 */

package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

var errInjected = errors.New("injected failure")

// recordingOps wraps the real ops, appending each op name to *rec. syncDir
// records the directory it was asked to sync in *dirs.
func recordingOps(rec *[]string, dirs *[]string) fsOps {
	real := defaultFSOps()
	return fsOps{
		write: func(f *os.File, b []byte) error {
			*rec = append(*rec, "write")
			return real.write(f, b)
		},
		syncFile: func(f *os.File) error {
			*rec = append(*rec, "syncFile")
			return real.syncFile(f)
		},
		close: func(f *os.File) error {
			*rec = append(*rec, "close")
			return real.close(f)
		},
		rename: func(o, n string) error {
			*rec = append(*rec, "rename")
			return real.rename(o, n)
		},
		syncDir: func(dir string) error {
			*rec = append(*rec, "syncDir")
			*dirs = append(*dirs, dir)
			return real.syncDir(dir)
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

func TestWriteFileAtomicSyncsInDurableOrder(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(dir, "id.key")
	var rec, dirs []string

	if err := writeFileAtomicWith(recordingOps(&rec, &dirs), path, []byte("new"), 0o600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"write", "syncFile", "close", "rename", "syncDir"}
	if !slices.Equal(rec, want) {
		t.Errorf("op order = %v, want %v", rec, want)
	}
	if !slices.Equal(dirs, []string{dir}) {
		t.Errorf("syncDir dirs = %v, want [%s]", dirs, dir)
	}
	assertFile(t, path, []byte("new"), 0o600)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("parent mode = %o, want 700", fi.Mode().Perm())
	}
	assertNoTempFiles(t, dir)
}

func TestWriteFileAtomicFileSyncFailureLeavesTargetUntouched(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	var rec, dirs []string
	ops := recordingOps(&rec, &dirs)
	ops.syncFile = func(*os.File) error {
		rec = append(rec, "syncFile")
		return errInjected
	}

	err := writeFileAtomicWith(ops, path, []byte("new"), 0o600)
	if !errors.Is(err, errInjected) {
		t.Errorf("err = %v, want wrapping %v", err, errInjected)
	}
	if slices.Contains(rec, "rename") {
		t.Errorf("rename called after file sync failure; ops = %v", rec)
	}
	assertFile(t, path, []byte("old"), 0o600)
	assertNoTempFiles(t, dir)
}

func TestWriteFileAtomicDirSyncFailureReturnsError(t *testing.T) {
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
			dir := t.TempDir()
			path := filepath.Join(dir, "id.key")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			var rec, dirs []string
			ops := recordingOps(&rec, &dirs)
			ops.syncDir = func(string) error {
				rec = append(rec, "syncDir")
				return tc.cause
			}

			err := writeFileAtomicWith(ops, path, []byte("new"), 0o600)
			if !errors.Is(err, tc.cause) {
				t.Errorf("err = %v, want wrapping %v", err, tc.cause)
			}
			assertFile(t, path, []byte("new"), 0o600)
			assertNoTempFiles(t, dir)
		})
	}
}

func TestWriteFileAtomicDirSyncUnsupportedIsIgnored(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		cause   error
		wantErr bool
	}{
		{"EINVAL", syscall.EINVAL, false},
		{"ENOTSUP", syscall.ENOTSUP, false},
		{"control_EIO_still_returned", syscall.EIO, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "id.key")
			var rec, dirs []string
			ops := recordingOps(&rec, &dirs)
			ops.syncDir = func(string) error {
				rec = append(rec, "syncDir")
				return tc.cause
			}

			err := writeFileAtomicWith(ops, path, []byte("new"), 0o600)
			if !slices.Contains(rec, "syncDir") {
				t.Errorf("syncDir not called; ops = %v", rec)
			}
			if tc.wantErr {
				if !errors.Is(err, tc.cause) {
					t.Errorf("err = %v, want wrapping %v", err, tc.cause)
				}
			} else if err != nil {
				t.Errorf("err = %v, want nil for unsupported dir sync", err)
			}
			assertFile(t, path, []byte("new"), 0o600)
		})
	}
}
