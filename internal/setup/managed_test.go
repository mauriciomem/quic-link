package setup_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/setup"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sub", "quic-link.conf")
}

func TestWrite_CreatesThenIsIdempotent(t *testing.T) {
	p := tmpPath(t)
	body := setup.Body("[Resolve]", "DNS=127.0.0.1:15353")

	if got, err := setup.Write(p, body, 0o644); err != nil || got != setup.Created {
		t.Fatalf("first write: %v %v", got, err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644 whatever the umask says", fi.Mode().Perm())
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("content = %q", got)
	}

	// Writing the same thing again must change nothing at all, so a caller can
	// skip restarting a service that did not need restarting.
	before := fi.ModTime()
	if got, err := setup.Write(p, body, 0o644); err != nil || got != setup.Unchanged {
		t.Fatalf("second write: %v %v", got, err)
	}
	after, _ := os.Stat(p)
	if !after.ModTime().Equal(before) {
		t.Error("an unchanged write must not touch the file")
	}
}

func TestWrite_ReplacesOurOwnStaleFile(t *testing.T) {
	p := tmpPath(t)
	if _, err := setup.Write(p, setup.Body("suffix = old"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := setup.Write(p, setup.Body("suffix = new"), 0o644)
	if err != nil || got != setup.Updated {
		t.Fatalf("got %v %v, want Updated", got, err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "new") {
		t.Errorf("content = %q", b)
	}
}

// TestWrite_RefusesSomebodyElsesFile is the rule that makes undo safe. A file
// that happens to share the path but was not written here is somebody's
// configuration, and overwriting it would be indistinguishable from vandalism.
func TestWrite_RefusesSomebodyElsesFile(t *testing.T) {
	p := tmpPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("[Resolve]\nDNS=9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := setup.Write(p, setup.Body("ours"), 0o644)
	if !errors.Is(err, setup.ErrNotOurs) {
		t.Fatalf("error = %v, want a refusal naming the file", err)
	}
	if !strings.Contains(err.Error(), p) {
		t.Errorf("the refusal must name the file: %v", err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "[Resolve]\nDNS=9.9.9.9\n" {
		t.Error("the file was modified despite the refusal")
	}
}

// TestWrite_RefusesASymlinkAtTheDestination: following it would write wherever
// whoever planted it chose.
func TestWrite_RefusesASymlinkAtTheDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "somewhere-else")
	if err := os.WriteFile(target, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "quic-link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := setup.Write(link, setup.Body("ours"), 0o644)
	if !errors.Is(err, setup.ErrNotRegular) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "original\n" {
		t.Error("the symlink was followed and its target was overwritten")
	}
}

func TestWrite_RefusesADirectoryOrDevice(t *testing.T) {
	dir := t.TempDir()
	inTheWay := filepath.Join(dir, "quic-link.conf")
	if err := os.Mkdir(inTheWay, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Write(inTheWay, setup.Body("ours"), 0o644); !errors.Is(err, setup.ErrNotRegular) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

// TestWrite_LeavesNoTemporaryFileBehind: a stray file in a resolver directory
// is inert but untidy, and a reader finding one would rightly wonder.
func TestWrite_LeavesNoTemporaryFileBehind(t *testing.T) {
	p := tmpPath(t)
	if _, err := setup.Write(p, setup.Body("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".quic-link.tmp-") {
			t.Errorf("left behind %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want just the file", len(entries))
	}
}

func TestRemove(t *testing.T) {
	p := tmpPath(t)

	// Nothing there: not an error, and nothing claimed.
	if removed, err := setup.Remove(p); err != nil || removed {
		t.Fatalf("removing nothing: %v %v", removed, err)
	}

	if _, err := setup.Write(p, setup.Body("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if removed, err := setup.Remove(p); err != nil || !removed {
		t.Fatalf("removing ours: %v %v", removed, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}

	// Twice is a no-op.
	if removed, err := setup.Remove(p); err != nil || removed {
		t.Fatalf("removing twice: %v %v", removed, err)
	}
}

// TestRemove_RefusesSomebodyElsesFile is the same rule from the other side, and
// is the one that stops undo from deleting a stranger's configuration.
func TestRemove_RefusesSomebodyElsesFile(t *testing.T) {
	p := tmpPath(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Remove(p); !errors.Is(err, setup.ErrNotOurs) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("the file was removed despite the refusal")
	}
}

// TestRemove_RefusesAFileWhoseMarkerWasRemoved: taking the marker off is how a
// user says "this is mine now", and it has to be honoured.
func TestRemove_RefusesAFileWhoseMarkerWasRemoved(t *testing.T) {
	p := tmpPath(t)
	if _, err := setup.Write(p, setup.Body("[Resolve]", "DNS=127.0.0.1:15353"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	stripped := strings.TrimPrefix(string(b), setup.Marker+"\n")
	if err := os.WriteFile(p, []byte(stripped), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Remove(p); !errors.Is(err, setup.ErrNotOurs) {
		t.Fatalf("error = %v, want a refusal once the marker is gone", err)
	}
	if _, err := setup.Write(p, setup.Body("x"), 0o644); !errors.Is(err, setup.ErrNotOurs) {
		t.Fatalf("write error = %v, want the same refusal", err)
	}
}
