/**
 * @spec-handoff
 * @interface readStateFile(path string) ([]byte, error)  // open O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC, fstat -> regular + checkPrivate, read via io.LimitReader(1 MiB + 1)
 * @interface upsertPairedWith(o pairedOpts, path, name, addr, pin string, now time.Time) error; pairedOpts{write func(path string, data []byte, perm os.FileMode) error}; defaultPairedOpts() = {atomicfile.Write}
 * @behavior
 *   - authorized_clients and paired.toml are read through readStateFile: > 1 MiB -> &MalformedError{Path, Line: 0, Reason: "file larger than 1 MiB"}; exactly 1 MiB loads; writers refuse an oversize file and leave it
 *   - readStateFile refuses what it opened if it is not a private regular file (FIFO, symlink -> ELOOP, dir, 0666) with ErrUnsafePath, never blocking; a missing file is fs.ErrNotExist
 *   - A non-ENOENT stat error (ENAMETOOLONG) is a plain error: errors.Is(syscall.ENAMETOOLONG), never ErrUnsafePath
 *   - Writers refuse a pre-existing .lock with any group/other bit (perm&0o077) with ErrUnsafePath naming it ("is readable or writable by group or others (mode %04o)"; "chmod 600"); the lock is never chmod'ed; an absent lock is created 0600
 *   - Every exported entry point taking a path (and OpenAuthorized) refuses a relative or non-clean path (filepath.Clean(p) != p) with ErrUnsafePath before touching the file system
 *   - writePaired re-checks the directory after the write: an unsafe directory -> ErrUnsafePath (the file is written; the next load refuses it)
 * @edge-cases
 *   - State files keep the 0o022 rule: a 0644 authorized_clients with a 0600 lock is accepted
 * @see ./perm.go ./authorized.go ./paired.go
 */

package pairstate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/mauriciomem/quic-link/internal/atomicfile"
)

const mib = 1 << 20

// pairedContent returns valid paired.toml content of size bytes holding one
// server, padded with TOML comment lines.
func pairedContent(size int, pin string) string {
	var b strings.Builder
	b.WriteString("[servers.home]\naddr = \"h.example.net:4433\"\npin = \"" + pin + "\"\npaired_at = 2026-11-14T10:00:00Z\n")
	for b.Len() < size {
		n := size - b.Len()
		switch {
		case n >= 1002:
			b.WriteString("# " + strings.Repeat("x", 999) + "\n")
		case n >= 3:
			b.WriteString("# " + strings.Repeat("x", n-3) + "\n")
		default:
			b.WriteString(strings.Repeat("\n", n))
		}
	}
	return b.String()
}

func wantSizeCapError(t *testing.T, what string, err error, path string) {
	t.Helper()
	var me *MalformedError
	if !errors.As(err, &me) {
		t.Fatalf("%s = %v, want a *MalformedError", what, err)
	}
	if me.Path != path || me.Line != 0 || me.Reason != "file larger than 1 MiB" {
		t.Errorf("%s = %+v, want {Path: %q, Line: 0, Reason: \"file larger than 1 MiB\"}", what, *me, path)
	}
}

func TestReadState_SizeCap(t *testing.T) {
	p, q := testPin("cap-p"), testPin("cap-q")

	t.Run("authorized_clients of exactly 1 MiB loads", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, oversizeAuthorized(mib, p))
		res, err := LoadAuthorized(path)
		if err != nil || len(res.Entries) != 1 || res.Entries[0].Pin != p {
			t.Errorf("LoadAuthorized(1 MiB) = (%d entries, %v), want the one entry", len(res.Entries), err)
		}
	})
	t.Run("authorized_clients one byte over is rejected", func(t *testing.T) {
		_, path := holderDir(t)
		content := oversizeAuthorized(mib+1, p)
		writeRaw(t, path, content)
		_, err := LoadAuthorized(path)
		wantSizeCapError(t, "LoadAuthorized(1 MiB + 1)", err, path)
		_, err = LoadAuthorizedAtStart(path)
		if !errors.Is(err, ErrColdStart) || !errors.Is(err, ErrMalformed) {
			t.Errorf("LoadAuthorizedAtStart(1 MiB + 1) = %v, want ErrColdStart and ErrMalformed", err)
		}
		if _, err := AppendAuthorized(path, Entry{Pin: q, State: StateUnconfirmed}); !errors.Is(err, ErrMalformed) {
			t.Errorf("AppendAuthorized on an oversize file = %v, want ErrMalformed", err)
		}
		if got := readRaw(t, path); got != content {
			t.Error("AppendAuthorized changed an oversize file")
		}
	})
	t.Run("paired.toml of exactly 1 MiB loads", func(t *testing.T) {
		dir, _ := holderDir(t)
		path := filepath.Join(dir, "paired.toml")
		writeRaw(t, path, pairedContent(mib, p))
		got, err := LoadPaired(path)
		if err != nil || len(got) != 1 || got["home"].Pin != p {
			t.Errorf("LoadPaired(1 MiB) = (%v, %v), want the one server", got, err)
		}
	})
	t.Run("paired.toml one byte over is rejected", func(t *testing.T) {
		dir, _ := holderDir(t)
		path := filepath.Join(dir, "paired.toml")
		content := pairedContent(mib+1, p)
		writeRaw(t, path, content)
		_, err := LoadPaired(path)
		wantSizeCapError(t, "LoadPaired(1 MiB + 1)", err, path)
		if err := UpsertPaired(path, "office", "o.example.net:4433", q, clockT2); !errors.Is(err, ErrMalformed) {
			t.Errorf("UpsertPaired on an oversize file = %v, want ErrMalformed", err)
		}
		if got := readRaw(t, path); got != content {
			t.Error("UpsertPaired changed an oversize file")
		}
	})

	// The open helper re-checks what it actually opened, so a file swapped in
	// after the Lstat check is refused too. These call it directly, which is
	// the deterministic stand-in for a swap between Lstat and open.
	t.Run("open helper", func(t *testing.T) {
		cases := []struct {
			name    string
			prepare func(t *testing.T, dir, path string) (fifo string)
			check   func(t *testing.T, path string, data []byte, err error)
		}{
			{"private regular file", func(t *testing.T, _, path string) string {
				writeRaw(t, path, "hello\n")
				return ""
			}, func(t *testing.T, _ string, data []byte, err error) {
				if err != nil || string(data) != "hello\n" {
					t.Errorf("readStateFile = (%q, %v), want the content", data, err)
				}
			}},
			{"exactly 1 MiB", func(t *testing.T, _, path string) string {
				writeRaw(t, path, strings.Repeat("a", mib))
				return ""
			}, func(t *testing.T, _ string, data []byte, err error) {
				if err != nil || len(data) != mib {
					t.Errorf("readStateFile = (%d bytes, %v), want 1 MiB", len(data), err)
				}
			}},
			{"1 MiB + 1", func(t *testing.T, _, path string) string {
				writeRaw(t, path, strings.Repeat("a", mib+1))
				return ""
			}, func(t *testing.T, path string, _ []byte, err error) {
				wantSizeCapError(t, "readStateFile(1 MiB + 1)", err, path)
			}},
			{"missing", func(*testing.T, string, string) string { return "" },
				func(t *testing.T, _ string, _ []byte, err error) {
					if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrUnsafePath) {
						t.Errorf("readStateFile = %v, want fs.ErrNotExist", err)
					}
				}},
			{"FIFO", func(t *testing.T, _, path string) string {
				mustDo(t, unix.Mkfifo(path, 0o600))
				return path
			}, wantUnsafe},
			{"symlink to a private file", func(t *testing.T, dir, path string) string {
				writeRaw(t, filepath.Join(dir, "real"), "hello\n")
				mustDo(t, os.Symlink(filepath.Join(dir, "real"), path))
				return ""
			}, wantUnsafe},
			{"directory", func(t *testing.T, _, path string) string {
				mustDo(t, os.Mkdir(path, 0o700))
				return ""
			}, wantUnsafe},
			{"file 0666", func(t *testing.T, _, path string) string {
				writeRaw(t, path, "hello\n")
				mustDo(t, os.Chmod(path, 0o666))
				return ""
			}, wantUnsafe},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dir, path := holderDir(t)
				fifo := tc.prepare(t, dir, path)
				var data []byte
				err := runGuarded(t, fifo, func() error {
					var err error
					data, err = readStateFile(path)
					return err
				})
				tc.check(t, path, data, err)
			})
		}
	})
}

func wantUnsafe(t *testing.T, _ string, _ []byte, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnsafePath) {
		t.Errorf("readStateFile = %v, want ErrUnsafePath", err)
	}
}

// allPathOps are every exported pairstate entry point that takes a path,
// each run against a seeded, private state directory.
func allPathOps() []struct {
	name, file string
	run        func(path string) error
} {
	p, n := testPin("paths-p"), testPin("paths-n")
	return []struct {
		name, file string
		run        func(path string) error
	}{
		{"LoadAuthorized", "authorized_clients", func(path string) error { _, err := LoadAuthorized(path); return err }},
		{"LoadAuthorizedAtStart", "authorized_clients", func(path string) error { _, err := LoadAuthorizedAtStart(path); return err }},
		{"AppendAuthorized", "authorized_clients", func(path string) error {
			_, err := AppendAuthorized(path, Entry{Pin: n, State: StateUnconfirmed})
			return err
		}},
		{"RemoveAuthorized", "authorized_clients", func(path string) error { _, err := RemoveAuthorized(path, p); return err }},
		{"PromoteAuthorized", "authorized_clients", func(path string) error { return PromoteAuthorized(path, p) }},
		{"OpenAuthorized", "authorized_clients", func(path string) error { _, err := OpenAuthorized(path, nil); return err }},
		{"LoadPaired", "paired.toml", func(path string) error { _, err := LoadPaired(path); return err }},
		{"UpsertPaired", "paired.toml", func(path string) error {
			return UpsertPaired(path, "office", "o.example.net:4433", n, clockT2)
		}},
		{"ForgetPaired", "paired.toml", func(path string) error { return ForgetPaired(path, "home") }},
	}
}

func seedFor(file string) string {
	if file == "paired.toml" {
		return pairedContent(0, testPin("paths-p"))
	}
	return testPin("paths-p") + " state=unconfirmed\n"
}

func TestVerifyState_PlainStatErrorIsNotUnsafePath(t *testing.T) {
	long := strings.Repeat("n", 300)
	for _, op := range allPathOps() {
		if op.name == "OpenAuthorized" {
			continue // covered by TestAuthorizedHolder_ColdStart
		}
		for _, shape := range []struct {
			name string
			path func(dir, file string) string
		}{
			{"300-byte file name", func(dir, _ string) string { return filepath.Join(dir, long) }},
			{"300-byte directory name", func(dir, file string) string { return filepath.Join(dir, long, file) }},
		} {
			t.Run(shape.name+"/"+op.name, func(t *testing.T) {
				dir, _ := holderDir(t)
				err := op.run(shape.path(dir, op.file))
				if err == nil {
					t.Fatalf("%s = nil, want an ENAMETOOLONG error", op.name)
				}
				if errors.Is(err, ErrUnsafePath) {
					t.Errorf("%s = %v, must not match ErrUnsafePath: a plain stat error is not an unsafe path", op.name, err)
				}
				if !errors.Is(err, syscall.ENAMETOOLONG) {
					t.Errorf("%s = %v, want it to wrap ENAMETOOLONG", op.name, err)
				}
			})
		}
	}
}

func TestWithLock_RefusesLockReadableByOthers(t *testing.T) {
	p, n := testPin("lockbits-p"), testPin("lockbits-n")
	const file = "authorized_clients"
	seed := p + " state=unconfirmed\n"
	writers := []stateOp{}
	for _, op := range authorizedOps(p, n) {
		if !op.reader {
			writers = append(writers, op)
		}
	}

	for _, op := range writers {
		t.Run("lock absent: created 0600/"+op.name, func(t *testing.T) {
			dir := seedState(t, t.TempDir(), file, seed, false)
			path := filepath.Join(dir, file)
			if err := op.run(path); err != nil {
				t.Fatalf("%s = %v, want nil", op.name, err)
			}
			assertMode(t, path+".lock", 0o600)
		})
		t.Run("lock 0600: accepted with a 0644 state file/"+op.name, func(t *testing.T) {
			dir := seedState(t, t.TempDir(), file, seed, true)
			path := filepath.Join(dir, file)
			mustDo(t, os.Chmod(path, 0o644))
			if err := op.run(path); err != nil {
				t.Errorf("%s = %v, want nil", op.name, err)
			}
		})
		for _, mode := range []os.FileMode{0o640, 0o604, 0o610, 0o601} {
			t.Run("lock "+modeOctal(mode)+"/"+op.name, func(t *testing.T) {
				dir := seedState(t, t.TempDir(), file, seed, true)
				path, lock := filepath.Join(dir, file), filepath.Join(dir, file+".lock")
				mustDo(t, os.Chmod(lock, mode)) // explicit: a create mode would be masked by the umask
				assertMode(t, lock, mode)
				before := listDir(t, dir)

				err := op.run(path)

				if !errors.Is(err, ErrUnsafePath) {
					t.Fatalf("%s with a %04o lock = %v, want ErrUnsafePath", op.name, mode, err)
				}
				want := lock + " is readable or writable by group or others (mode " + modeOctal(mode) + ")"
				if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "chmod 600") {
					t.Errorf("error %q, want it to contain %q and \"chmod 600\"", err, want)
				}
				assertMode(t, lock, mode) // never re-moded
				if got := readRaw(t, path); got != seed {
					t.Errorf("state file changed to %q", got)
				}
				if after := listDir(t, dir); !reflect.DeepEqual(after, before) {
					t.Errorf("directory listing changed from %q to %q", before, after)
				}
			})
		}
	}
	t.Run("readers ignore a 0640 lock", func(t *testing.T) {
		dir := seedState(t, t.TempDir(), file, seed, true)
		mustDo(t, os.Chmod(filepath.Join(dir, file+".lock"), 0o640))
		if _, err := LoadAuthorized(filepath.Join(dir, file)); err != nil {
			t.Errorf("LoadAuthorized with a 0640 lock = %v, want nil", err)
		}
	})
}

// modeOctal renders the permission bits as four octal digits.
func modeOctal(m os.FileMode) string {
	const digits = "01234567"
	v := uint32(m.Perm())
	return string([]byte{'0', digits[(v>>6)&7], digits[(v>>3)&7], digits[v&7]})
}

func TestStatePaths_RequireCleanAbsolute(t *testing.T) {
	shapes := []struct {
		name string
		// path builds the path to pass from root (holding state/, the seeded
		// state directory) and chdirs when the path is relative.
		path func(t *testing.T, root, file string) string
	}{
		{"relative file name", func(t *testing.T, root, file string) string {
			t.Chdir(filepath.Join(root, "state"))
			return file
		}},
		{"relative path", func(t *testing.T, root, file string) string {
			t.Chdir(root)
			return "state/" + file
		}},
		{"dot-dot component", func(t *testing.T, root, file string) string {
			mustDo(t, os.Mkdir(filepath.Join(root, "state", "sub"), 0o700))
			return root + "/state/sub/../" + file
		}},
		{"dot component", func(t *testing.T, root, file string) string { return root + "/state/./" + file }},
		{"double slash", func(t *testing.T, root, file string) string { return root + "/state//" + file }},
		{"trailing slash", func(t *testing.T, root, file string) string { return root + "/state/" + file + "/" }},
	}
	for _, op := range allPathOps() {
		for _, sh := range shapes {
			t.Run(sh.name+"/"+op.name, func(t *testing.T) {
				root := t.TempDir()
				seed := seedFor(op.file)
				dir := seedState(t, root, op.file, seed, false)
				path := sh.path(t, root, op.file)
				before := listDir(t, dir)

				err := op.run(path)

				if !errors.Is(err, ErrUnsafePath) {
					t.Errorf("%s(%q) = %v, want ErrUnsafePath", op.name, path, err)
				}
				if errors.Is(err, ErrColdStart) {
					t.Errorf("%s(%q) = %v, must not match ErrColdStart", op.name, path, err)
				}
				if got := readRaw(t, filepath.Join(dir, op.file)); got != seed {
					t.Errorf("seed file changed to %q", got)
				}
				if after := listDir(t, dir); !reflect.DeepEqual(after, before) {
					t.Errorf("directory listing changed from %q to %q", before, after)
				}
			})
		}
		t.Run("control: clean absolute path/"+op.name, func(t *testing.T) {
			dir := seedState(t, t.TempDir(), op.file, seedFor(op.file), false)
			if err := op.run(filepath.Join(dir, op.file)); err != nil {
				t.Errorf("%s = %v, want nil", op.name, err)
			}
		})
	}
}

func TestUpsertPaired_ChecksDirItCreated(t *testing.T) {
	p := testPin("upsert-dir-p")
	// widen is a write that succeeds and then leaves the directory unsafe, as
	// if it had been created (or swapped in) group/other-writable.
	widen := pairedOpts{write: func(path string, data []byte, perm os.FileMode) error {
		if err := atomicfile.Write(path, data, perm); err != nil {
			return err
		}
		return os.Chmod(filepath.Dir(path), 0o777)
	}}

	t.Run("directory created by the write is re-checked", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "paired.toml")
		err := upsertPairedWith(widen, path, "home", "h.example.net:4433", p, clockT1)
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("upsertPairedWith = %v, want ErrUnsafePath", err)
		}
		if _, err := LoadPaired(path); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("LoadPaired after the write = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("existing directory is re-checked", func(t *testing.T) {
		dir := seedState(t, t.TempDir(), "paired.toml", pairedContent(0, p), false)
		err := upsertPairedWith(widen, filepath.Join(dir, "paired.toml"), "office", "o.example.net:4433", p, clockT1)
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("upsertPairedWith = %v, want ErrUnsafePath", err)
		}
	})
	t.Run("control: default write creates a private directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "paired.toml")
		if err := UpsertPaired(path, "home", "h.example.net:4433", p, clockT1); err != nil {
			t.Fatalf("UpsertPaired = %v, want nil", err)
		}
		assertMode(t, filepath.Dir(path), 0o700)
		assertMode(t, path, 0o600)
		if got, err := LoadPaired(path); err != nil || got["home"].Pin != p {
			t.Errorf("LoadPaired = (%v, %v), want the record", got, err)
		}
	})
	t.Run("control: a seam write that keeps the directory private", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new", "paired.toml")
		if err := upsertPairedWith(pairedOpts{write: atomicfile.Write}, path, "home", "h.example.net:4433", p, clockT1); err != nil {
			t.Errorf("upsertPairedWith = %v, want nil", err)
		}
	})
	t.Run("default options use atomicfile.Write", func(t *testing.T) {
		if defaultPairedOpts().write == nil {
			t.Fatal("defaultPairedOpts().write is nil")
		}
	})
}
