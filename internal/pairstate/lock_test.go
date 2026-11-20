/**
 * @spec-handoff
 * @interface appendAuthorizedWith(o lockOpts, path string, e Entry) (bool, error); removeAuthorizedWith(o lockOpts, path, prefix string) (Entry, error); promoteAuthorizedWith(o lockOpts, path, pin string) error
 * @interface type lockOpts struct{ timeout, interval time.Duration }; func defaultLockOpts() lockOpts  // {5s, 10ms}
 * @behavior
 *   - Every writer opens path+".lock" (0600, O_RDWR|O_CREATE|O_CLOEXEC) and holds unix.Flock LOCK_EX across read-modify-atomicfile.Write
 *   - LOCK_EX|LOCK_NB is retried every interval until timeout -> ErrLockTimeout, file untouched; the exported writers use defaultLockOpts()
 *   - Readers (LoadAuthorized) never lock
 * @edge-cases
 *   - flock is advisory: hand edits bypass it; NFS/FUSE lock semantics are not covered by these tests
 * @see ./authorized.go
 */

package pairstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// holdLock takes LOCK_EX on lockPath through its own open file description,
// so any writer in this process must wait for it exactly like another process.
func holdLock(t *testing.T, lockPath string) (release func()) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		t.Fatalf("test could not take the lock: %v", err)
	}
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}
	t.Cleanup(release)
	return release
}

func TestAuthorizedWriters_WaitForExclusiveLock(t *testing.T) {
	p, n := testPin("lock-p"), testPin("lock-new")
	content := p + " state=unconfirmed\n"
	short := lockOpts{timeout: 150 * time.Millisecond, interval: 10 * time.Millisecond}

	t.Run("default options", func(t *testing.T) {
		if got, want := defaultLockOpts(), (lockOpts{timeout: 5 * time.Second, interval: 10 * time.Millisecond}); got != want {
			t.Errorf("defaultLockOpts() = %+v, want %+v", got, want)
		}
	})

	writers := map[string]func(path string) error{
		"append": func(path string) error {
			_, err := appendAuthorizedWith(short, path, Entry{Pin: n, State: StateUnconfirmed})
			return err
		},
		"remove": func(path string) error {
			_, err := removeAuthorizedWith(short, path, p)
			return err
		},
		"promote": func(path string) error { return promoteAuthorizedWith(short, path, p) },
	}
	for name, write := range writers {
		t.Run(name+" times out while the lock is held", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authorized_clients")
			writeRaw(t, path, content)
			holdLock(t, path+".lock")

			start := time.Now()
			err := write(path)
			elapsed := time.Since(start)
			if !errors.Is(err, ErrLockTimeout) {
				t.Errorf("err = %v, want ErrLockTimeout", err)
			}
			if elapsed < short.timeout {
				t.Errorf("gave up after %v, before the %v timeout", elapsed, short.timeout)
			}
			if elapsed > 3*time.Second {
				t.Errorf("waited %v: the injected timeout was not used", elapsed)
			}
			if got := readRaw(t, path); got != content {
				t.Errorf("file changed without the lock: %q", got)
			}
		})
	}

	t.Run("reader does not take the lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_clients")
		writeRaw(t, path, content)
		holdLock(t, path+".lock")
		res, err := LoadAuthorized(path)
		if err != nil || len(res.Entries) != 1 {
			t.Errorf("LoadAuthorized under a held lock = (%+v, %v), want one entry", res, err)
		}
	})

	t.Run("writer proceeds once the lock is released", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authorized_clients")
		writeRaw(t, path, content)
		release := holdLock(t, path+".lock")

		type result struct {
			added bool
			err   error
		}
		done := make(chan result, 1)
		go func() {
			added, err := appendAuthorizedWith(lockOpts{timeout: 10 * time.Second, interval: 10 * time.Millisecond},
				path, Entry{Pin: n, State: StateUnconfirmed})
			done <- result{added, err}
		}()

		select {
		case r := <-done:
			t.Fatalf("writer returned (%v, %v) while the lock was held", r.added, r.err)
		case <-time.After(200 * time.Millisecond):
		}
		if got := readRaw(t, path); got != content {
			t.Errorf("file changed while the lock was held: %q", got)
		}
		release()

		select {
		case r := <-done:
			if r.err != nil || !r.added {
				t.Errorf("writer after release = (%v, %v), want (true, nil)", r.added, r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("writer did not finish after the lock was released")
		}
		if want := content + n + " state=unconfirmed\n"; readRaw(t, path) != want {
			t.Errorf("file = %q, want %q", readRaw(t, path), want)
		}
	})
}
