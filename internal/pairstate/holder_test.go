/**
 * @spec-handoff
 * @interface OpenAuthorized(path string, onStale func(StaleEvent)) (*AuthorizedHolder, error); openAuthorizedWith(o holderOpts, path, onStale) // holderOpts{now func() time.Time}; defaultHolderOpts() sets now = time.Now
 * @interface (*AuthorizedHolder).Entries() []Entry; (*AuthorizedHolder).Source(cfgList, flagList []string) func() map[string]struct{}
 * @interface type StaleEvent struct{ Path string; Err error; Serving int; LoadedAt time.Time; Recovered bool }
 * @behavior
 *   - Cold start: missing file/dir -> empty holder; malformed or > 1 MiB -> ErrColdStart+ErrMalformed; unsafe or unclean path -> ErrUnsafePath (no ErrColdStart); other errors pass through; nil holder on error
 *   - Entries re-reads on every call: success (missing file = empty) replaces the last good set; any rejection keeps it
 *   - Rejection -> StaleEvent{Path, Err, Serving: len(last good), LoadedAt: when it loaded}: once per distinct cause (Err text), again once 60 s passed since the last emission; first good read after a rejection -> one StaleEvent{Recovered: true}
 *   - onStale runs after the holder lock is released (it may call Entries); nil onStale drops events
 *   - Source(cfg, flags)() = EffectiveAuthorized(cfg, flags, Entries()); non-empty flags -> the file is never read; fresh map per call
 * @edge-cases
 *   - FIFO / symlink / 0666 / 0777 dir / EACCES / oversize after start: last good list served, no hang (2 s watchdog)
 *   - Exactly 60 s is not pinned: 60 s - 1 ms stays quiet, 60 s + 1 ms emits
 * @see ./holder.go ./authorized.go
 */

package pairstate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

// fakeClock is an injectable holder clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// staleRecorder collects StaleEvents.
type staleRecorder struct {
	mu  sync.Mutex
	evs []StaleEvent
}

func (r *staleRecorder) record(e StaleEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
}

func (r *staleRecorder) events() []StaleEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]StaleEvent(nil), r.evs...)
}

// pinsOf returns the sorted pins of es.
func pinsOf(es []Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Pin)
	}
	slices.Sort(out)
	return out
}

func sortedPins(pins ...string) []string {
	out := append([]string(nil), pins...)
	slices.Sort(out)
	return out
}

func setKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// entriesGuarded calls h.Entries under the FIFO watchdog.
func entriesGuarded(t *testing.T, h *AuthorizedHolder, fifo string) []Entry {
	t.Helper()
	var got []Entry
	_ = runGuarded(t, fifo, func() error {
		got = h.Entries()
		return nil
	})
	return got
}

// oversizeAuthorized returns valid authorized_clients content of size bytes
// that lists pins, padded with comment lines.
func oversizeAuthorized(size int, pins ...string) string {
	var b strings.Builder
	for _, p := range pins {
		b.WriteString(p + " state=confirmed\n")
	}
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

// holderDir makes root/state (0700) and returns the authorized_clients path.
func holderDir(t *testing.T) (dir, path string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "state")
	mustDo(t, os.Mkdir(dir, 0o700))
	return dir, filepath.Join(dir, "authorized_clients")
}

func TestAuthorizedHolder_ColdStart(t *testing.T) {
	a, b := testPin("cold-a"), testPin("cold-b")
	good := a + " state=confirmed\n" + b + " state=unconfirmed\n"

	t.Run("default options use the wall clock", func(t *testing.T) {
		o := defaultHolderOpts()
		if o.now == nil {
			t.Fatal("defaultHolderOpts().now is nil, want time.Now")
		}
		before := time.Now()
		got := o.now()
		if got.Before(before) || got.After(time.Now()) {
			t.Errorf("defaultHolderOpts().now() = %v, not the current time", got)
		}
	})

	t.Run("good file: entries loaded", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, good)
		h, err := OpenAuthorized(path, nil)
		if err != nil || h == nil {
			t.Fatalf("OpenAuthorized = (%v, %v), want a holder", h, err)
		}
		if got, want := pinsOf(h.Entries()), sortedPins(a, b); !slices.Equal(got, want) {
			t.Errorf("Entries() = %q, want %q", got, want)
		}
	})

	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
	}{
		{"missing file", func(t *testing.T) string { _, p := holderDir(t); return p }},
		{"missing directory", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "absent", "authorized_clients")
		}},
	} {
		t.Run(tc.name+": empty holder, no event", func(t *testing.T) {
			rec := &staleRecorder{}
			h, err := OpenAuthorized(tc.path(t), rec.record)
			if err != nil || h == nil {
				t.Fatalf("OpenAuthorized = (%v, %v), want an empty holder", h, err)
			}
			if got := h.Entries(); len(got) != 0 {
				t.Errorf("Entries() = %v, want none", got)
			}
			if evs := rec.events(); len(evs) != 0 {
				t.Errorf("events = %+v, want none", evs)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		content string
	}{
		{"malformed", a + " state=confirmed\nnot-a-pin\n"},
		{"larger than 1 MiB", oversizeAuthorized(1<<20+1, a)},
	} {
		t.Run(tc.name+": ErrColdStart and ErrMalformed", func(t *testing.T) {
			_, path := holderDir(t)
			writeRaw(t, path, tc.content)
			h, err := OpenAuthorized(path, nil)
			if !errors.Is(err, ErrColdStart) || !errors.Is(err, ErrMalformed) {
				t.Errorf("OpenAuthorized = %v, want an error matching ErrColdStart and ErrMalformed", err)
			}
			if errors.Is(err, ErrUnsafePath) {
				t.Errorf("OpenAuthorized = %v, must not match ErrUnsafePath", err)
			}
			if h != nil {
				t.Errorf("OpenAuthorized returned a holder %v with its error", h)
			}
		})
	}

	unsafe := []struct {
		name    string
		prepare func(t *testing.T) (path, fifo string)
	}{
		{"file 0666", func(t *testing.T) (string, string) {
			_, path := holderDir(t)
			writeRaw(t, path, good)
			mustDo(t, os.Chmod(path, 0o666))
			return path, ""
		}},
		{"dir 0777", func(t *testing.T) (string, string) {
			dir, path := holderDir(t)
			writeRaw(t, path, good)
			mustDo(t, os.Chmod(dir, 0o777))
			return path, ""
		}},
		{"file is a symlink", func(t *testing.T) (string, string) {
			dir, path := holderDir(t)
			writeRaw(t, filepath.Join(dir, "real"), good)
			mustDo(t, os.Symlink(filepath.Join(dir, "real"), path))
			return path, ""
		}},
		{"file is a FIFO", func(t *testing.T) (string, string) {
			_, path := holderDir(t)
			mustDo(t, unix.Mkfifo(path, 0o600))
			return path, path
		}},
		{"relative path", func(t *testing.T) (string, string) { return "authorized_clients", "" }},
		{"path with ..", func(t *testing.T) (string, string) {
			dir, path := holderDir(t)
			writeRaw(t, path, good)
			mustDo(t, os.Mkdir(filepath.Join(dir, "sub"), 0o700))
			return dir + "/sub/../authorized_clients", ""
		}},
		{"path with a trailing slash", func(t *testing.T) (string, string) {
			_, path := holderDir(t)
			return path + "/", ""
		}},
	}
	for _, tc := range unsafe {
		t.Run(tc.name+": ErrUnsafePath without ErrColdStart", func(t *testing.T) {
			path, fifo := tc.prepare(t)
			var h *AuthorizedHolder
			err := runGuarded(t, fifo, func() error {
				var err error
				h, err = OpenAuthorized(path, nil)
				return err
			})
			if !errors.Is(err, ErrUnsafePath) {
				t.Errorf("OpenAuthorized(%q) = %v, want ErrUnsafePath", path, err)
			}
			if errors.Is(err, ErrColdStart) {
				t.Errorf("OpenAuthorized(%q) = %v, must not match ErrColdStart", path, err)
			}
			if h != nil {
				t.Errorf("OpenAuthorized returned a holder with its error")
			}
		})
	}

	t.Run("plain stat error passes through", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), strings.Repeat("n", 300))
		h, err := OpenAuthorized(path, nil)
		if !errors.Is(err, syscall.ENAMETOOLONG) {
			t.Errorf("OpenAuthorized = %v, want ENAMETOOLONG", err)
		}
		if errors.Is(err, ErrUnsafePath) || errors.Is(err, ErrColdStart) {
			t.Errorf("OpenAuthorized = %v, must match neither ErrUnsafePath nor ErrColdStart", err)
		}
		if h != nil {
			t.Errorf("OpenAuthorized returned a holder with its error")
		}
	})

	t.Run("unreadable file passes through", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode 0000 file")
		}
		_, path := holderDir(t)
		writeRaw(t, path, good)
		mustDo(t, os.Chmod(path, 0))
		h, err := OpenAuthorized(path, nil)
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("OpenAuthorized = %v, want a permission error", err)
		}
		if errors.Is(err, ErrUnsafePath) || errors.Is(err, ErrColdStart) {
			t.Errorf("OpenAuthorized = %v, must match neither ErrUnsafePath nor ErrColdStart", err)
		}
		if h != nil {
			t.Errorf("OpenAuthorized returned a holder with its error")
		}
	})
}

func TestAuthorizedHolder_ReloadKeepsLastKnownGood(t *testing.T) {
	a, b, c := testPin("lkg-a"), testPin("lkg-b"), testPin("lkg-c")
	good := a + " state=confirmed\n" + b + " state=unconfirmed\n"
	lkg := sortedPins(a, b)

	causes := []struct {
		name      string
		rootSkip  bool
		breakFile func(t *testing.T, dir, path string) (fifo string)
		match     func(err error) bool
		want      string
	}{
		{"malformed line", false, func(t *testing.T, _, path string) string {
			writeRaw(t, path, a+" state=confirmed\n"+c+" state=confirmed\nnot-a-pin\n")
			return ""
		}, func(err error) bool { return errors.Is(err, ErrMalformed) }, "ErrMalformed"},
		{"file is a symlink", false, func(t *testing.T, dir, path string) string {
			writeRaw(t, filepath.Join(dir, "other"), c+" state=confirmed\n")
			mustDo(t, os.Remove(path))
			mustDo(t, os.Symlink(filepath.Join(dir, "other"), path))
			return ""
		}, func(err error) bool { return errors.Is(err, ErrUnsafePath) }, "ErrUnsafePath"},
		{"file 0666", false, func(t *testing.T, _, path string) string {
			writeRaw(t, path, c+" state=confirmed\n")
			mustDo(t, os.Chmod(path, 0o666))
			return ""
		}, func(err error) bool { return errors.Is(err, ErrUnsafePath) }, "ErrUnsafePath"},
		{"dir 0777", false, func(t *testing.T, dir, path string) string {
			writeRaw(t, path, c+" state=confirmed\n")
			mustDo(t, os.Chmod(dir, 0o777))
			return ""
		}, func(err error) bool { return errors.Is(err, ErrUnsafePath) }, "ErrUnsafePath"},
		{"file is a FIFO", false, func(t *testing.T, _, path string) string {
			mustDo(t, os.Remove(path))
			mustDo(t, unix.Mkfifo(path, 0o600))
			return path
		}, func(err error) bool { return errors.Is(err, ErrUnsafePath) }, "ErrUnsafePath"},
		{"larger than 1 MiB", false, func(t *testing.T, _, path string) string {
			writeRaw(t, path, oversizeAuthorized(1<<20+1, a, c))
			return ""
		}, func(err error) bool {
			var me *MalformedError
			return errors.As(err, &me) && me.Line == 0
		}, "*MalformedError with Line 0"},
		{"unreadable file", true, func(t *testing.T, _, path string) string {
			writeRaw(t, path, c+" state=confirmed\n")
			mustDo(t, os.Chmod(path, 0))
			return ""
		}, func(err error) bool { return errors.Is(err, fs.ErrPermission) && !errors.Is(err, ErrUnsafePath) }, "a permission error"},
	}
	for _, tc := range causes {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rootSkip && os.Geteuid() == 0 {
				t.Skip("root reads a mode 0000 file")
			}
			dir, path := holderDir(t)
			writeRaw(t, path, good)
			clock := newFakeClock()
			loadedAt := clock.now()
			rec := &staleRecorder{}
			h, err := openAuthorizedWith(holderOpts{now: clock.now}, path, rec.record)
			if err != nil {
				t.Fatalf("openAuthorizedWith = %v", err)
			}
			if got := pinsOf(entriesGuarded(t, h, "")); !slices.Equal(got, lkg) {
				t.Fatalf("Entries() before the change = %q, want %q", got, lkg)
			}
			clock.advance(time.Second)

			fifo := tc.breakFile(t, dir, path)
			got := pinsOf(entriesGuarded(t, h, fifo))
			if !slices.Equal(got, lkg) {
				t.Errorf("Entries() after %s = %q, want the last good list %q", tc.name, got, lkg)
			}
			var src map[string]struct{}
			_ = runGuarded(t, fifo, func() error { src = h.Source(nil, nil)(); return nil })
			if got := setKeys(src); !slices.Equal(got, lkg) {
				t.Errorf("Source()() after %s = %q, want the last good list %q", tc.name, got, lkg)
			}

			evs := rec.events()
			if len(evs) != 1 {
				t.Fatalf("events after %s = %+v, want exactly one stale event", tc.name, evs)
			}
			ev := evs[0]
			if ev.Recovered || ev.Err == nil || !tc.match(ev.Err) {
				t.Errorf("event = %+v, want a stale event whose Err is %s", ev, tc.want)
			}
			if ev.Path != path || ev.Serving != 2 || !ev.LoadedAt.Equal(loadedAt) {
				t.Errorf("event = {Path %q, Serving %d, LoadedAt %v}, want {%q, 2, %v}", ev.Path, ev.Serving, ev.LoadedAt, path, loadedAt)
			}
			if ev.Err != nil && !printableASCII(ev.Err.Error()) {
				t.Errorf("event error %q is not printable ASCII", ev.Err.Error())
			}

			// Repair: the next read replaces the last good list.
			mustDo(t, os.Chmod(dir, 0o700))
			mustDo(t, os.RemoveAll(path))
			writeRaw(t, path, c+" state=confirmed\n")
			if got, want := pinsOf(entriesGuarded(t, h, "")), []string{c}; !slices.Equal(got, want) {
				t.Errorf("Entries() after repair = %q, want %q", got, want)
			}
			if evs := rec.events(); len(evs) != 2 || !evs[1].Recovered || evs[1].Err != nil {
				t.Errorf("events after repair = %+v, want the stale event then one recovery event", evs)
			}
		})
	}
}

func TestAuthorizedHolder_StaleEventRateLimited(t *testing.T) {
	a, b, c := testPin("rate-a"), testPin("rate-b"), testPin("rate-c")
	good := a + " state=confirmed\n" + b + " state=confirmed\n"
	malformed := a + " state=confirmed\nnot-a-pin\n"

	t.Run("one event per cause, again after 60 s, one recovery event", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, good)
		clock := newFakeClock()
		loadedAt := clock.now()
		rec := &staleRecorder{}
		h, err := openAuthorizedWith(holderOpts{now: clock.now}, path, rec.record)
		if err != nil {
			t.Fatalf("openAuthorizedWith = %v", err)
		}
		count := func(t *testing.T, step string, want int) {
			t.Helper()
			h.Entries()
			if got := len(rec.events()); got != want {
				t.Fatalf("%s: %d events, want %d (events %+v)", step, got, want, rec.events())
			}
		}
		count(t, "good file", 0)

		writeRaw(t, path, malformed)
		count(t, "first rejection", 1)
		count(t, "same cause again", 1)
		clock.advance(60*time.Second - time.Millisecond)
		count(t, "same cause 1 ms before 60 s", 1)
		clock.advance(2 * time.Millisecond)
		count(t, "same cause 60 s after the first event", 2)
		count(t, "same cause right after the repeat", 2)
		clock.advance(30 * time.Second)
		count(t, "same cause 30 s after the repeat", 2)

		mustDo(t, os.Chmod(path, 0o666))
		count(t, "a different cause", 3)
		count(t, "the different cause again", 3)

		evs := rec.events()
		for i, ev := range evs {
			if ev.Recovered || ev.Serving != 2 || !ev.LoadedAt.Equal(loadedAt) || ev.Path != path {
				t.Errorf("event %d = %+v, want a stale event serving 2 entries loaded at %v", i, ev, loadedAt)
			}
		}
		if !errors.Is(evs[0].Err, ErrMalformed) || !errors.Is(evs[1].Err, ErrMalformed) || !errors.Is(evs[2].Err, ErrUnsafePath) {
			t.Errorf("event causes = %v / %v / %v, want malformed, malformed, unsafe", evs[0].Err, evs[1].Err, evs[2].Err)
		}

		mustDo(t, os.Chmod(path, 0o600))
		writeRaw(t, path, c+" state=confirmed\n")
		count(t, "recovery", 4)
		count(t, "good again", 4)
		clock.advance(2 * time.Minute)
		count(t, "good two minutes later", 4)
		if ev := rec.events()[3]; !ev.Recovered || ev.Err != nil || ev.Path != path {
			t.Errorf("recovery event = %+v, want {Recovered: true, Err: nil, Path: %q}", ev, path)
		}

		// A new outage after the recovery is reported at once, even with the
		// cause seen before.
		writeRaw(t, path, malformed)
		count(t, "the earlier cause after recovery", 5)
		if ev := rec.events()[4]; ev.Recovered || ev.Serving != 1 || !ev.LoadedAt.Equal(clock.now()) {
			t.Errorf("event after recovery = %+v, want a stale event serving 1 entry loaded at %v", ev, clock.now())
		}
	})

	t.Run("a recovery resets the rate limit: the same cause within 60 s is reported again", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, good)
		clock := newFakeClock()
		rec := &staleRecorder{}
		h, err := openAuthorizedWith(holderOpts{now: clock.now}, path, rec.record)
		if err != nil {
			t.Fatalf("openAuthorizedWith = %v", err)
		}

		writeRaw(t, path, malformed)
		h.Entries()
		clock.advance(10 * time.Second)
		writeRaw(t, path, good)
		h.Entries()
		clock.advance(10 * time.Second) // 20 s after the first event: still inside its 60 s window
		writeRaw(t, path, malformed)
		h.Entries()

		evs := rec.events()
		if len(evs) != 3 {
			t.Fatalf("events = %+v, want stale, recovery, stale: the same cause after a recovery must be reported even within 60 s", evs)
		}
		if evs[0].Recovered || !errors.Is(evs[0].Err, ErrMalformed) {
			t.Errorf("event 0 = %+v, want a malformed stale event", evs[0])
		}
		if !evs[1].Recovered || evs[1].Err != nil {
			t.Errorf("event 1 = %+v, want a recovery event", evs[1])
		}
		if evs[2].Recovered || !errors.Is(evs[2].Err, ErrMalformed) || evs[2].Err.Error() != evs[0].Err.Error() {
			t.Errorf("event 2 = %+v, want a stale event with the first event's cause %q", evs[2], evs[0].Err)
		}
	})

	t.Run("LoadedAt of the cold-start set is the injected clock's", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, good)
		clock := newFakeClock()
		openedAt := clock.now()
		rec := &staleRecorder{}
		h, err := openAuthorizedWith(holderOpts{now: clock.now}, path, rec.record)
		if err != nil {
			t.Fatalf("openAuthorizedWith = %v", err)
		}
		clock.advance(5 * time.Second)
		writeRaw(t, path, malformed) // no read between the open and the rejection
		h.Entries()
		if evs := rec.events(); len(evs) != 1 || !evs[0].LoadedAt.Equal(openedAt) || evs[0].Serving != 2 {
			t.Errorf("events = %+v, want one stale event serving 2 entries loaded at %v", evs, openedAt)
		}
	})

	t.Run("missing file is not a rejection", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, good)
		rec := &staleRecorder{}
		h, err := openAuthorizedWith(holderOpts{now: newFakeClock().now}, path, rec.record)
		if err != nil {
			t.Fatalf("openAuthorizedWith = %v", err)
		}
		writeRaw(t, path, malformed)
		h.Entries()
		mustDo(t, os.Remove(path))
		if got := h.Entries(); len(got) != 0 {
			t.Errorf("Entries() with the file deleted = %q, want none", pinsOf(got))
		}
		if evs := rec.events(); len(evs) != 2 || !evs[1].Recovered {
			t.Errorf("events = %+v, want one stale event then one recovery event", evs)
		}
	})

	t.Run("nil onStale drops events", func(t *testing.T) {
		_, path := holderDir(t)
		writeRaw(t, path, good)
		h, err := openAuthorizedWith(holderOpts{now: newFakeClock().now}, path, nil)
		if err != nil {
			t.Fatalf("openAuthorizedWith = %v", err)
		}
		writeRaw(t, path, malformed)
		if got, want := pinsOf(h.Entries()), sortedPins(a, b); !slices.Equal(got, want) {
			t.Errorf("Entries() = %q, want the last good list %q", got, want)
		}
	})

	t.Run("event is delivered after the holder lock is released", func(t *testing.T) {
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
		_, path := holderDir(t)
		writeRaw(t, path, good)
		var (
			h         *AuthorizedHolder
			calls     int
			reentered []string
		)
		onStale := func(StaleEvent) {
			calls++
			if calls == 1 {
				reentered = pinsOf(h.Entries()) // deadlocks if called under the lock
			}
		}
		var err error
		h, err = openAuthorizedWith(holderOpts{now: newFakeClock().now}, path, onStale)
		if err != nil {
			t.Fatalf("openAuthorizedWith = %v", err)
		}
		writeRaw(t, path, malformed)
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.Entries()
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Entries did not return within 2 s: onStale was called while the holder lock was held")
		}
		if calls != 1 {
			t.Errorf("onStale called %d times, want 1", calls)
		}
		if want := sortedPins(a, b); !slices.Equal(reentered, want) {
			t.Errorf("Entries() from inside onStale = %q, want %q", reentered, want)
		}
	})
}

func TestAuthorizedHolder_RevocationSeenNextRead(t *testing.T) {
	pins := make([]string, 30)
	var b strings.Builder
	for i := range pins {
		pins[i] = testPin(fmt.Sprintf("revoke-%02d", i))
		b.WriteString(pins[i] + " state=confirmed\n")
	}
	cfgPin := testPin("revoke-cfg")
	_, path := holderDir(t)
	writeRaw(t, path, b.String())
	rec := &staleRecorder{}
	h, err := OpenAuthorized(path, rec.record)
	if err != nil {
		t.Fatalf("OpenAuthorized = %v", err)
	}
	src := h.Source([]string{cfgPin}, nil)
	if got, want := setKeys(src()), sortedPins(append([]string{cfgPin}, pins...)...); !slices.Equal(got, want) {
		t.Fatalf("Source()() = %d pins, want %d", len(got), len(want))
	}

	revoked := pins[17]
	if _, err := RemoveAuthorized(path, revoked); err != nil {
		t.Fatalf("RemoveAuthorized: %v", err)
	}
	rest := slices.DeleteFunc(slices.Clone(pins), func(p string) bool { return p == revoked })
	if got := pinsOf(h.Entries()); !slices.Equal(got, sortedPins(rest...)) {
		t.Errorf("Entries() after removing a line = %d pins (revoked present: %v), want the other %d",
			len(got), slices.Contains(got, revoked), len(rest))
	}
	if _, ok := src()[revoked]; ok {
		t.Error("the source captured before the removal still admits the revoked pin")
	}

	mustDo(t, os.Remove(path))
	if got := h.Entries(); len(got) != 0 {
		t.Errorf("Entries() with the file deleted = %d entries, want none", len(got))
	}
	if got := setKeys(src()); !slices.Equal(got, []string{cfgPin}) {
		t.Errorf("Source()() with the file deleted = %q, want only the config pin", got)
	}
	if evs := rec.events(); len(evs) != 0 {
		t.Errorf("events = %+v, want none: revocation is not a rejection", evs)
	}
}

func TestAuthorizedHolder_ConcurrentReadersAndWriter(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	first := testPin("conc-first")
	_, path := holderDir(t)
	writeRaw(t, path, first+" state=confirmed\n")
	rec := &staleRecorder{}
	h, err := OpenAuthorized(path, rec.record)
	if err != nil {
		t.Fatalf("OpenAuthorized = %v", err)
	}
	const n = 40
	added := []string{first}
	for i := 0; i < n; i++ {
		added = append(added, testPin(fmt.Sprintf("conc-%02d", i)))
	}
	known := set(added...)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			src := h.Source(nil, nil)
			last := 0
			for {
				var got []string
				if r%2 == 0 {
					got = pinsOf(h.Entries())
				} else {
					got = setKeys(src())
				}
				if len(got) < last {
					errs <- fmt.Sprintf("reader %d saw %d pins after %d: a read returned an older or partial file", r, len(got), last)
					return
				}
				last = len(got)
				for _, p := range got {
					if _, ok := known[p]; !ok {
						errs <- fmt.Sprintf("reader %d saw unknown pin %q", r, p)
						return
					}
				}
				select {
				case <-stop:
					return
				default:
				}
			}
		}(r)
	}
	for _, p := range added[1:] {
		if _, err := AppendAuthorized(path, Entry{Pin: p, State: StateUnconfirmed}); err != nil {
			t.Errorf("AppendAuthorized: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if got := pinsOf(h.Entries()); !slices.Equal(got, sortedPins(added...)) {
		t.Errorf("Entries() after the writer = %d pins, want %d", len(got), len(added))
	}
	if evs := rec.events(); len(evs) != 0 {
		t.Errorf("events = %+v, want none", evs)
	}
}

func TestAuthorizedHolder_SourceFlagsReplaceFile(t *testing.T) {
	filePin, cfgPin, flagPin := testPin("src-file"), testPin("src-cfg"), testPin("src-flag")
	dir, path := holderDir(t)
	writeRaw(t, path, filePin+" state=unconfirmed\n")
	rec := &staleRecorder{}
	h, err := openAuthorizedWith(holderOpts{now: newFakeClock().now}, path, rec.record)
	if err != nil {
		t.Fatalf("openAuthorizedWith = %v", err)
	}

	withFlags := h.Source([]string{cfgPin}, []string{flagPin})
	if got := setKeys(withFlags()); !slices.Equal(got, []string{flagPin}) {
		t.Errorf("Source(cfg, flags)() = %q, want only the flag pin", got)
	}

	// The file goes bad; with flags it is never read, so nothing notices.
	writeRaw(t, path, "not-a-pin\n")
	if got := setKeys(withFlags()); !slices.Equal(got, []string{flagPin}) {
		t.Errorf("Source(cfg, flags)() with a malformed file = %q, want only the flag pin", got)
	}
	mustDo(t, os.Remove(path))
	mustDo(t, unix.Mkfifo(path, 0o600))
	var got map[string]struct{}
	_ = runGuarded(t, path, func() error { got = withFlags(); return nil })
	if keys := setKeys(got); !slices.Equal(keys, []string{flagPin}) {
		t.Errorf("Source(cfg, flags)() with a FIFO = %q, want only the flag pin", keys)
	}
	if evs := rec.events(); len(evs) != 0 {
		t.Errorf("events = %+v, want none: with flags the file is never read", evs)
	}

	// Control: without flags the same file is read and rejected.
	mustDo(t, os.Remove(path))
	writeRaw(t, path, "not-a-pin\n")
	for _, flags := range [][]string{nil, {}} {
		if keys := setKeys(h.Source([]string{cfgPin}, flags)()); !slices.Equal(keys, sortedPins(cfgPin, filePin)) {
			t.Errorf("Source(cfg, %q)() = %q, want the config pin and the last good file pin", flags, keys)
		}
	}
	if evs := rec.events(); len(evs) != 1 || !errors.Is(evs[0].Err, ErrMalformed) {
		t.Errorf("events without flags = %+v, want one malformed stale event", evs)
	}

	t.Run("each call returns a fresh map", func(t *testing.T) {
		writeRaw(t, filepath.Join(dir, "authorized_clients"), filePin+" state=confirmed\n")
		src := h.Source([]string{cfgPin}, nil)
		m := src()
		m[flagPin] = struct{}{}
		delete(m, cfgPin)
		if keys := setKeys(src()); !slices.Equal(keys, sortedPins(cfgPin, filePin)) {
			t.Errorf("Source()() after mutating an earlier result = %q, want %q", keys, sortedPins(cfgPin, filePin))
		}
		fm := withFlags()
		delete(fm, flagPin)
		if keys := setKeys(withFlags()); !slices.Equal(keys, []string{flagPin}) {
			t.Errorf("Source(cfg, flags)() after mutating an earlier result = %q, want only the flag pin", keys)
		}
	})
}
