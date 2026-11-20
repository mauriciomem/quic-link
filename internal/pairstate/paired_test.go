/**
 * @spec-handoff
 * @interface LoadPaired(path string) (map[string]PairedServer, error); UpsertPaired(path, name, addr, pin string, now time.Time) error; ForgetPaired(path, name string) error
 * @behavior
 *   - File shape: [servers.NAME] addr, pin, paired_at (go-toml/v2); missing file -> empty map, nil
 *   - Upsert creates or replaces NAME with paired_at = now (injected clock); other servers kept; file 0600, dir 0700
 *   - Forget removes NAME; unknown NAME -> ErrNotFound, file untouched
 *   - Load and write validate: pin ParsePinStrict, name non-empty without '.', whitespace or control chars, addr non-empty
 *   - Invalid entry or bad TOML on load -> *MalformedError{Path, Line: 0, Reason} matching ErrMalformed
 * @edge-cases
 *   - Unknown keys are ignored on load (forward compatible), not rejected
 *   - No lock is taken on paired.toml (single-operator client verb)
 * @see ./paired.go
 */

package pairstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	clockT1 = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	clockT2 = time.Date(2026, 11, 20, 8, 30, 15, 0, time.UTC)
)

func assertPaired(t *testing.T, got, want map[string]PairedServer) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("servers = %+v, want %+v", got, want)
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("server %q missing; got %+v", name, got)
			continue
		}
		if g.Addr != w.Addr || g.Pin != w.Pin || !g.PairedAt.Equal(w.PairedAt) {
			t.Errorf("server %q = %+v, want %+v", name, g, w)
		}
	}
}

func TestLoadPaired_MissingFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "paired.toml")
	got, err := LoadPaired(path)
	if err != nil {
		t.Fatalf("LoadPaired(missing) err = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("LoadPaired(missing) = %#v, want empty non-nil map", got)
	}
	assertAbsent(t, path)
}

func TestUpsertPaired_RoundTripModesAndOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "quic-link")
	path := filepath.Join(dir, "paired.toml")
	pa, pa2, pb := testPin("paired-a"), testPin("paired-a2"), testPin("paired-b")

	if err := UpsertPaired(path, "home", "home.example.net:4433", pa, clockT1); err != nil {
		t.Fatalf("UpsertPaired: %v", err)
	}
	assertMode(t, dir, 0o700)
	assertMode(t, path, 0o600)
	got, err := LoadPaired(path)
	if err != nil {
		t.Fatalf("LoadPaired: %v", err)
	}
	assertPaired(t, got, map[string]PairedServer{"home": {Addr: "home.example.net:4433", Pin: pa, PairedAt: clockT1}})

	if err := UpsertPaired(path, "office", "192.0.2.10:4433", pb, clockT1); err != nil {
		t.Fatalf("UpsertPaired(office): %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpsertPaired(path, "home", "198.51.100.7:4433", pa2, clockT2); err != nil {
		t.Fatalf("UpsertPaired(overwrite): %v", err)
	}
	assertMode(t, path, 0o600)
	got, err = LoadPaired(path)
	if err != nil {
		t.Fatalf("LoadPaired: %v", err)
	}
	assertPaired(t, got, map[string]PairedServer{
		"home":   {Addr: "198.51.100.7:4433", Pin: pa2, PairedAt: clockT2},
		"office": {Addr: "192.0.2.10:4433", Pin: pb, PairedAt: clockT1},
	})

	t.Run("rejects invalid input and leaves the file untouched", func(t *testing.T) {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cases := map[string][3]string{ // name, addr, pin
			"empty name":         {"", "a:1", pb},
			"name with dot":      {"a.b", "a:1", pb},
			"name with space":    {"a b", "a:1", pb},
			"name with tab":      {"a\tb", "a:1", pb},
			"name with newline":  {"a\nb", "a:1", pb},
			"name with control":  {"a\x01b", "a:1", pb},
			"empty addr":         {"new", "", pb},
			"empty pin":          {"new", "a:1", ""},
			"pin with space":     {"new", "a:1", pb + " "},
			"non-canonical pin":  {"new", "a:1", nonCanonicalVariant(t, pb)},
			"overwrite, bad pin": {"home", "a:1", "nope"},
		}
		for name, c := range cases {
			if err := UpsertPaired(path, c[0], c[1], c[2], clockT2); err == nil {
				t.Errorf("%s: UpsertPaired accepted %q", name, c)
			}
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("invalid upserts changed the file:\n%s", after)
		}
		missing := filepath.Join(t.TempDir(), "paired.toml")
		if err := UpsertPaired(missing, "a.b", "a:1", pb, clockT1); err == nil {
			t.Errorf("UpsertPaired(new file, bad name) accepted")
		}
		assertAbsent(t, missing)
	})
}

func TestForgetPaired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paired.toml")
	pa, pb := testPin("forget-a"), testPin("forget-b")
	for _, s := range []struct{ name, addr, pin string }{{"home", "h:1", pa}, {"office", "o:1", pb}} {
		if err := UpsertPaired(path, s.name, s.addr, s.pin, clockT1); err != nil {
			t.Fatalf("UpsertPaired(%s): %v", s.name, err)
		}
	}

	if err := ForgetPaired(path, "home"); err != nil {
		t.Fatalf("ForgetPaired(home): %v", err)
	}
	got, err := LoadPaired(path)
	if err != nil {
		t.Fatalf("LoadPaired: %v", err)
	}
	assertPaired(t, got, map[string]PairedServer{"office": {Addr: "o:1", Pin: pb, PairedAt: clockT1}})
	assertMode(t, path, 0o600)

	before := readRaw(t, path)
	if err := ForgetPaired(path, "home"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ForgetPaired(already forgotten) = %v, want ErrNotFound", err)
	}
	if err := ForgetPaired(path, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ForgetPaired(unknown) = %v, want ErrNotFound", err)
	}
	if readRaw(t, path) != before {
		t.Errorf("forgetting an unknown name changed the file")
	}

	missing := filepath.Join(t.TempDir(), "paired.toml")
	if err := ForgetPaired(missing, "home"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ForgetPaired(missing file) = %v, want ErrNotFound", err)
	}
	assertAbsent(t, missing)
}

func TestLoadPaired_RejectsInvalidEntries(t *testing.T) {
	p := testPin("load-paired")
	entry := func(name, addr, pin string) string {
		return "[servers." + name + "]\naddr = \"" + addr + "\"\npin = \"" + pin + "\"\npaired_at = 2026-11-14T10:00:00Z\n"
	}

	bad := map[string]string{
		"not TOML":            "[servers.home\naddr = ",
		"wrong type":          "[servers.home]\naddr = 5\npin = \"" + p + "\"\n",
		"bad pin":             entry("home", "h:1", "not-a-pin"),
		"non-canonical pin":   entry("home", "h:1", nonCanonicalVariant(t, p)),
		"pin with whitespace": entry("home", "h:1", p+" "),
		"missing pin":         "[servers.home]\naddr = \"h:1\"\n",
		"empty addr":          entry("home", "", p),
		"name with dot":       entry(`"a.b"`, "h:1", p),
		"name with space":     entry(`"a b"`, "h:1", p),
		"empty name":          entry(`""`, "h:1", p),
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "paired.toml")
			writeRaw(t, path, content)
			got, err := LoadPaired(path)
			var me *MalformedError
			if !errors.As(err, &me) || !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want *MalformedError matching ErrMalformed", err)
			}
			if me.Path != path || me.Reason == "" {
				t.Errorf("MalformedError = %+v, want Path %q and a Reason", me, path)
			}
			if len(got) != 0 {
				t.Errorf("rejected file returned servers %+v", got)
			}
		})
	}

	t.Run("unknown keys are ignored", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "paired.toml")
		writeRaw(t, path, "version_hint = 2\n"+entry("home", "h:1", p)+"label = \"laptop\"\n\n[future]\nx = 1\n")
		got, err := LoadPaired(path)
		if err != nil {
			t.Fatalf("LoadPaired with unknown keys: %v", err)
		}
		assertPaired(t, got, map[string]PairedServer{"home": {Addr: "h:1", Pin: p, PairedAt: clockT1}})
	})
	t.Run("valid file loads every server", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "paired.toml")
		q := testPin("load-paired-q")
		writeRaw(t, path, entry("home", "h:1", p)+entry("office-2", "o:1", q))
		got, err := LoadPaired(path)
		if err != nil {
			t.Fatalf("LoadPaired: %v", err)
		}
		want := map[string]PairedServer{
			"home":     {Addr: "h:1", Pin: p, PairedAt: clockT1},
			"office-2": {Addr: "o:1", Pin: q, PairedAt: clockT1},
		}
		assertPaired(t, got, want)
	})
}
