package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakeRunner struct {
	out []byte
	err error
}

func (f fakeRunner) run(context.Context, string, ...string) ([]byte, error) { return f.out, f.err }

// TestParseSystemdVersion uses the banners real distributions print. The text
// in parentheses varies; the number does not.
func TestParseSystemdVersion(t *testing.T) {
	cases := map[string]int{
		"systemd 259 (259.8-1.fc44)\n+PAM +AUDIT": 259,
		"systemd 259 (259.5-0ubuntu3)\n":          259,
		"systemd 246 (246.6-5)\n":                 246,
		"systemd 255 (255.4-1ubuntu8.4)\n":        255,
		"systemd v256.7-1.fc41 (256.7)\n":         256, // some builds prefix the number with a v
		"systemd 249 (249.11-0ubuntu3.12)\n":      249,
		"":                                        0,
		"not systemd at all":                      0,
	}
	for in, want := range cases {
		if got := parseSystemdVersion(in); got != want {
			t.Errorf("parseSystemdVersion(%q) = %d, want %d", strings.SplitN(in, "\n", 2)[0], got, want)
		}
	}
}

// resolvRoot builds a fake filesystem root whose resolver configuration is a
// symlink to target, or a plain file when target is empty.
func resolvRoot(t *testing.T, target string) string {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(etc, "resolv.conf")
	if target == "" {
		if err := os.WriteFile(p, []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return root
}

func TestDetectSystemd(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this describes the Linux resolver")
	}
	ctx := context.Background()
	good := fakeRunner{out: []byte("systemd 259 (259.8-1.fc44)\n")}

	t.Run("stub mode with a recent systemd is supported", func(t *testing.T) {
		r := detectSystemd(ctx, good, resolvRoot(t, "/run/systemd/resolve/stub-resolv.conf"))
		if r.Support != SystemdStub {
			t.Fatalf("support = %v (%s)", r.Support, r.Reason)
		}
		if r.SystemdVersion != 259 {
			t.Errorf("version = %d", r.SystemdVersion)
		}
	})

	// The finding that matters: resolved is running and healthy, but every
	// lookup goes straight to the upstream servers, so a drop-in would be
	// written, accepted, and silently ignored.
	t.Run("uplink mode is refused even though resolved is running", func(t *testing.T) {
		r := detectSystemd(ctx, good, resolvRoot(t, "/run/systemd/resolve/resolv.conf"))
		if r.Support != Unsupported {
			t.Fatal("uplink mode must be refused: a file written there does nothing")
		}
		if !strings.Contains(r.Reason, "ignored") {
			t.Errorf("the reason must say it would be ignored: %q", r.Reason)
		}
	})

	t.Run("a plain resolver configuration is refused", func(t *testing.T) {
		r := detectSystemd(ctx, good, resolvRoot(t, ""))
		if r.Support != Unsupported {
			t.Fatal("a plain file cannot name a port")
		}
		if !strings.Contains(r.Reason, "cannot name a port") {
			t.Errorf("reason = %q", r.Reason)
		}
	})

	t.Run("an old systemd is refused with its version named", func(t *testing.T) {
		old := fakeRunner{out: []byte("systemd 246 (246.6-5)\n")}
		r := detectSystemd(ctx, old, resolvRoot(t, "/run/systemd/resolve/stub-resolv.conf"))
		if r.Support != Unsupported {
			t.Fatal("246 is too old to name a resolver with a port")
		}
		if !strings.Contains(r.Reason, "246") || !strings.Contains(r.Reason, "247") {
			t.Errorf("the reason should name both versions: %q", r.Reason)
		}
	})

	t.Run("exactly the minimum version is supported", func(t *testing.T) {
		min := fakeRunner{out: []byte("systemd 247 (247)\n")}
		r := detectSystemd(ctx, min, resolvRoot(t, "/run/systemd/resolve/stub-resolv.conf"))
		if r.Support != SystemdStub {
			t.Fatalf("247 is the first version that works: %s", r.Reason)
		}
	})

	t.Run("no systemctl at all is refused, not an error", func(t *testing.T) {
		r := detectSystemd(ctx, fakeRunner{err: errors.New("not found")},
			resolvRoot(t, "/run/systemd/resolve/stub-resolv.conf"))
		if r.Support != Unsupported {
			t.Fatal("without a version there is nothing to rely on")
		}
	})

	t.Run("every refusal carries a recipe to follow by hand", func(t *testing.T) {
		for _, root := range []string{"", "/run/systemd/resolve/resolv.conf"} {
			r := detectSystemd(ctx, good, resolvRoot(t, root))
			if r.Manual == "" {
				t.Error("a refusal with no way forward is a dead end")
			}
			if r.Reason == "" {
				t.Error("a refusal must say why")
			}
		}
	})
}
