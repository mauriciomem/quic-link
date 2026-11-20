/**
 * @spec-handoff
 * @interface checkPrivate(path string, fi os.FileInfo, wantDir bool, euid int) error  // fi is the Lstat or fstat result
 * @interface ErrUnsafePath; every failure is fmt.Errorf("%w: %s %s", ErrUnsafePath, path, problem)
 * @behavior
 *   - problem, checked symlink first: "is a symbolic link" | "is not a directory" | "is not a regular file" (FIFO, device, socket, dir)
 *     | "has no ownership information" (Sys() not *syscall.Stat_t) | "is owned by uid %d, not %d" | "is writable by group or others (mode %04o)"
 *   - Private = owner == euid and perm&0o022 == 0: dir 0700/0755 and file 0600/0644 accepted
 *   - The state dir (filepath.Dir(path)), authorized_clients and paired.toml are Lstat-checked before any open, so a FIFO never blocks;
 *     the .lock is opened with O_NOFOLLOW, then fstat-checked (ELOOP -> "is a symbolic link")
 *   - Every reader and writer of an unsafe path fails with ErrUnsafePath (never ErrColdStart, never a *MalformedError),
 *     leaves the files and the directory listing unchanged; readers never touch the lock, so a bad .lock fails writers only
 * @edge-cases
 *   - Missing dir or file: readers return an empty result; a dangling .lock symlink's target is never created
 * @see ./perm.go
 */

package pairstate

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeInfo is an os.FileInfo with a chosen mode and Sys() value, so ownership
// by another user can be tested without root.
type fakeInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeInfo) Name() string       { return "fake" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return f.sys }

func TestCheckPrivate_Rules(t *testing.T) {
	const euid = 1000
	owned := &syscall.Stat_t{Uid: euid}
	foreign := &syscall.Stat_t{Uid: 1001}
	cases := []struct {
		name    string
		fi      fakeInfo
		wantDir bool
		problem string // "" = accepted
	}{
		{"dir 0700", fakeInfo{os.ModeDir | 0o700, owned}, true, ""},
		{"dir 0755", fakeInfo{os.ModeDir | 0o755, owned}, true, ""},
		{"dir 0770", fakeInfo{os.ModeDir | 0o770, owned}, true, "is writable by group or others (mode 0770)"},
		{"dir 0702", fakeInfo{os.ModeDir | 0o702, owned}, true, "is writable by group or others (mode 0702)"},
		{"dir owned by another user", fakeInfo{os.ModeDir | 0o700, foreign}, true, "is owned by uid 1001, not 1000"},
		{"symlink where a dir is wanted", fakeInfo{os.ModeSymlink | 0o777, owned}, true, "is a symbolic link"},
		{"symlink where a file is wanted", fakeInfo{os.ModeSymlink | 0o777, owned}, false, "is a symbolic link"},
		{"file where a dir is wanted", fakeInfo{0o600, owned}, true, "is not a directory"},
		{"dir where a file is wanted", fakeInfo{os.ModeDir | 0o700, owned}, false, "is not a regular file"},
		{"file 0600", fakeInfo{0o600, owned}, false, ""},
		{"file 0644", fakeInfo{0o644, owned}, false, ""},
		{"file 0660", fakeInfo{0o660, owned}, false, "is writable by group or others (mode 0660)"},
		{"file 0606", fakeInfo{0o606, owned}, false, "is writable by group or others (mode 0606)"},
		{"file owned by another user", fakeInfo{0o600, foreign}, false, "is owned by uid 1001, not 1000"},
		{"named pipe", fakeInfo{os.ModeNamedPipe | 0o600, owned}, false, "is not a regular file"},
		{"device", fakeInfo{os.ModeDevice | 0o600, owned}, false, "is not a regular file"},
		{"no ownership information", fakeInfo{os.ModeDir | 0o700, nil}, true, "has no ownership information"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const path = "/state/quic-link/x"
			err := checkPrivate(path, tc.fi, tc.wantDir, euid)
			if tc.problem == "" {
				if err != nil {
					t.Errorf("checkPrivate = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("checkPrivate = %v, want ErrUnsafePath", err)
			}
			if want := path + " " + tc.problem; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		})
	}
}

// fifoWatchdog is how long an operation may run before it counts as blocked
// on a FIFO.
const fifoWatchdog = 2 * time.Second

// runGuarded runs op and returns its error. If op is still running after
// fifoWatchdog, the test fails and fifo (when not "") is opened for writing
// and closed, so a reader blocked on it sees EOF and op can return; no
// goroutine outlives the call.
func runGuarded(t *testing.T, fifo string, op func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		return err
	case <-time.After(fifoWatchdog):
	}
	t.Errorf("blocked on FIFO: the operation did not return within %v", fifoWatchdog)
	if fifo == "" {
		return <-done
	}
	for {
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
		}
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// listDir returns the names in dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// unsafeCase prepares one unsafe layout. It returns the path to hand to the
// operations, the directory whose listing must not change, the file holding
// the seed ("" when there is none to read back) and the FIFO to unblock.
type unsafeCase struct {
	name     string
	lockOnly bool // readers never touch the lock, so they must succeed
	prepare  func(t *testing.T, root, file, seed string) (path, listed, seedFile, fifo string)
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// seedState creates root/state (0700) holding file with seed (0600) and, when
// withLock, file+".lock" (0600), so a correct implementation adds no entry.
func seedState(t *testing.T, root, file, seed string, withLock bool) string {
	t.Helper()
	dir := filepath.Join(root, "state")
	mustDo(t, os.Mkdir(dir, 0o700))
	mustDo(t, os.WriteFile(filepath.Join(dir, file), []byte(seed), 0o600))
	if withLock {
		mustDo(t, os.WriteFile(filepath.Join(dir, file+".lock"), nil, 0o600))
	}
	return dir
}

// dirAndFileCases are the unsafe layouts shared by authorized_clients and
// paired.toml. withLock pre-creates the lock so no new entry is expected.
func dirAndFileCases(withLock bool) []unsafeCase {
	plain := func(mutate func(t *testing.T, dir, path string)) func(t *testing.T, root, file, seed string) (string, string, string, string) {
		return func(t *testing.T, root, file, seed string) (string, string, string, string) {
			dir := seedState(t, root, file, seed, withLock)
			path := filepath.Join(dir, file)
			mutate(t, dir, path)
			return path, dir, path, ""
		}
	}
	return []unsafeCase{
		{name: "dir 0770", prepare: plain(func(t *testing.T, dir, _ string) { mustDo(t, os.Chmod(dir, 0o770)) })},
		{name: "dir 0707", prepare: plain(func(t *testing.T, dir, _ string) { mustDo(t, os.Chmod(dir, 0o707)) })},
		{name: "dir is a symlink", prepare: func(t *testing.T, root, file, seed string) (string, string, string, string) {
			dir := seedState(t, root, file, seed, withLock)
			link := filepath.Join(root, "link")
			mustDo(t, os.Symlink(dir, link))
			return filepath.Join(link, file), dir, filepath.Join(dir, file), ""
		}},
		{name: "file 0660", prepare: plain(func(t *testing.T, _, path string) { mustDo(t, os.Chmod(path, 0o660)) })},
		{name: "file 0606", prepare: plain(func(t *testing.T, _, path string) { mustDo(t, os.Chmod(path, 0o606)) })},
		{name: "file is a symlink", prepare: func(t *testing.T, root, file, seed string) (string, string, string, string) {
			dir := seedState(t, root, file, seed, withLock)
			path := filepath.Join(dir, file)
			real := filepath.Join(dir, "real-"+file)
			mustDo(t, os.Rename(path, real))
			mustDo(t, os.Symlink(real, path))
			return path, dir, real, ""
		}},
		{name: "file is a FIFO", prepare: func(t *testing.T, root, file, seed string) (string, string, string, string) {
			dir := seedState(t, root, file, seed, withLock)
			path := filepath.Join(dir, file)
			mustDo(t, os.Remove(path))
			mustDo(t, unix.Mkfifo(path, 0o600))
			return path, dir, "", path
		}},
	}
}

func lockCases() []unsafeCase {
	withLockShape := func(shape func(t *testing.T, dir, lock string)) func(t *testing.T, root, file, seed string) (string, string, string, string) {
		return func(t *testing.T, root, file, seed string) (string, string, string, string) {
			dir := seedState(t, root, file, seed, false)
			path := filepath.Join(dir, file)
			shape(t, dir, path+".lock")
			return path, dir, path, ""
		}
	}
	return []unsafeCase{
		{name: "lock is a dangling symlink", lockOnly: true, prepare: withLockShape(func(t *testing.T, dir, lock string) {
			mustDo(t, os.Symlink(filepath.Join(dir, "lock-target"), lock))
		})},
		{name: "lock is a symlink to a file", lockOnly: true, prepare: withLockShape(func(t *testing.T, dir, lock string) {
			target := filepath.Join(dir, "lock-target")
			mustDo(t, os.WriteFile(target, nil, 0o600))
			mustDo(t, os.Symlink(target, lock))
		})},
		{name: "lock 0606", lockOnly: true, prepare: withLockShape(func(t *testing.T, _, lock string) {
			mustDo(t, os.WriteFile(lock, nil, 0o600))
			mustDo(t, os.Chmod(lock, 0o606))
		})},
	}
}

type stateOp struct {
	name   string
	reader bool
	run    func(path string) error
}

func authorizedOps(p, n string) []stateOp {
	return []stateOp{
		{"LoadAuthorized", true, func(path string) error {
			res, err := LoadAuthorized(path)
			if err == nil && !reflect.DeepEqual(res.Entries, []Entry{{Pin: p, State: StateUnconfirmed}}) {
				return errors.New("unexpected entries " + formatEntries(res.Entries))
			}
			return err
		}},
		{"LoadAuthorizedAtStart", true, func(path string) error {
			res, err := LoadAuthorizedAtStart(path)
			if err == nil && !reflect.DeepEqual(res.Entries, []Entry{{Pin: p, State: StateUnconfirmed}}) {
				return errors.New("unexpected entries " + formatEntries(res.Entries))
			}
			return err
		}},
		{"AppendAuthorized", false, func(path string) error {
			_, err := AppendAuthorized(path, Entry{Pin: n, State: StateUnconfirmed})
			return err
		}},
		{"RemoveAuthorized", false, func(path string) error {
			_, err := RemoveAuthorized(path, p)
			return err
		}},
		{"PromoteAuthorized", false, func(path string) error { return PromoteAuthorized(path, p) }},
	}
}

func formatEntries(es []Entry) string {
	var b strings.Builder
	for _, e := range es {
		b.WriteString(formatLine(e) + ";")
	}
	return b.String()
}

// checkUnsafe runs op on the layout tc prepares and asserts the refusal.
func checkUnsafe(t *testing.T, tc unsafeCase, op stateOp, file, seed string) {
	t.Helper()
	root := t.TempDir()
	path, listed, seedFile, fifo := tc.prepare(t, root, file, seed)
	before := listDir(t, listed)

	err := runGuarded(t, fifo, func() error { return op.run(path) })

	if tc.lockOnly && op.reader {
		if err != nil {
			t.Errorf("%s with an unsafe lock = %v, want success: readers never touch the lock", op.name, err)
		}
	} else {
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s = %v, want ErrUnsafePath", op.name, err)
		}
		if errors.Is(err, ErrColdStart) {
			t.Errorf("%s = %v, must not match ErrColdStart", op.name, err)
		}
		var me *MalformedError
		if errors.As(err, &me) {
			t.Errorf("%s = %v, must not be a *MalformedError", op.name, err)
		}
	}
	if seedFile != "" {
		if got, rerr := os.ReadFile(seedFile); rerr != nil || string(got) != seed {
			t.Errorf("seed file %s = (%q, %v), want it unchanged", seedFile, got, rerr)
		}
	}
	if after := listDir(t, listed); !reflect.DeepEqual(after, before) {
		t.Errorf("directory listing changed from %q to %q", before, after)
	}
}

func TestAuthorizedFiles_RefuseUnsafePaths(t *testing.T) {
	p, n := testPin("unsafe-p"), testPin("unsafe-n")
	seed := p + " state=unconfirmed\n"
	const file = "authorized_clients"
	ops := authorizedOps(p, n)

	for _, tc := range append(dirAndFileCases(true), lockCases()...) {
		for _, op := range ops {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				t.Parallel()
				checkUnsafe(t, tc, op, file, seed)
			})
		}
	}
	t.Run("dangling lock symlink target is not created", func(t *testing.T) {
		root := t.TempDir()
		dir := seedState(t, root, file, seed, false)
		target := filepath.Join(dir, "lock-target")
		path := filepath.Join(dir, file)
		mustDo(t, os.Symlink(target, path+".lock"))
		if _, err := AppendAuthorized(path, Entry{Pin: n, State: StateUnconfirmed}); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("AppendAuthorized = %v, want ErrUnsafePath", err)
		}
		assertAbsent(t, target)
	})
	for _, op := range ops {
		t.Run("control: private dir, 0644 file and 0600 lock/"+op.name, func(t *testing.T) {
			t.Parallel()
			dir := seedState(t, t.TempDir(), file, seed, true)
			path := filepath.Join(dir, file)
			mustDo(t, os.Chmod(path, 0o644))
			if err := runGuarded(t, "", func() error { return op.run(path) }); err != nil {
				t.Errorf("%s on a private layout = %v, want nil", op.name, err)
			}
		})
	}
}

func TestPairedFile_RefusesUnsafePaths(t *testing.T) {
	p, q := testPin("unsafe-paired-p"), testPin("unsafe-paired-q")
	seed := "[servers.home]\naddr = \"h:1\"\npin = \"" + p + "\"\npaired_at = 2026-11-14T10:00:00Z\n"
	const file = "paired.toml"
	ops := []stateOp{
		{"LoadPaired", true, func(path string) error {
			got, err := LoadPaired(path)
			if err == nil && (len(got) != 1 || got["home"].Pin != p) {
				return errors.New("unexpected servers")
			}
			return err
		}},
		{"UpsertPaired", false, func(path string) error {
			return UpsertPaired(path, "office", "o.example.net:4433", q, clockT2)
		}},
		{"ForgetPaired", false, func(path string) error { return ForgetPaired(path, "home") }},
	}

	for _, tc := range dirAndFileCases(false) {
		for _, op := range ops {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				t.Parallel()
				checkUnsafe(t, tc, op, file, seed)
			})
		}
	}
	for _, op := range ops {
		t.Run("control: private dir and 0644 file/"+op.name, func(t *testing.T) {
			t.Parallel()
			dir := seedState(t, t.TempDir(), file, seed, false)
			path := filepath.Join(dir, file)
			mustDo(t, os.Chmod(path, 0o644))
			if err := runGuarded(t, "", func() error { return op.run(path) }); err != nil {
				t.Errorf("%s on a private layout = %v, want nil", op.name, err)
			}
		})
	}
}
