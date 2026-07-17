package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written. keygen prints its CONTRACT "pin:" line to stdout.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// parsePinLine extracts the pin from keygen's CONTRACT last line "pin: <base64>".
func parsePinLine(t *testing.T, out string) string {
	t.Helper()
	var pin string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if p, ok := strings.CutPrefix(line, "pin: "); ok {
			pin = strings.TrimSpace(p)
		}
	}
	if pin == "" {
		t.Fatalf("no 'pin:' line in keygen output: %q", out)
	}
	return pin
}

func TestKeygenIdempotentAndForce(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	// First run: creates the key + meta and prints a pin.
	out1, err := captureStdout(t, func() error { return runKeygen([]string{"--out", keyPath}) })
	if err != nil {
		t.Fatalf("keygen (create): %v", err)
	}
	pin1 := parsePinLine(t, out1)

	// Key file exists with 0600.
	if fi, err := os.Stat(keyPath); err != nil {
		t.Fatalf("stat key: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key mode = %o, want 0600", perm)
	}

	// Meta sidecar exists with 0600 and a parseable RFC3339 created time.
	metaPath := keyPath + ".meta"
	metaFi, err := os.Stat(metaPath)
	if err != nil {
		t.Fatalf("stat meta: %v", err)
	}
	if perm := metaFi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("meta mode = %o, want 0600", perm)
	}
	created1 := readMetaCreated(t, metaPath)

	// Second run without --force: idempotent — same pin, exit 0, meta unchanged.
	out2, err := captureStdout(t, func() error { return runKeygen([]string{"--out", keyPath}) })
	if err != nil {
		t.Fatalf("keygen (idempotent): %v", err)
	}
	if pin2 := parsePinLine(t, out2); pin2 != pin1 {
		t.Fatalf("idempotent keygen changed pin: %q -> %q", pin1, pin2)
	}
	if created2 := readMetaCreated(t, metaPath); !created2.Equal(created1) {
		t.Fatalf("idempotent keygen rewrote meta: %v -> %v", created1, created2)
	}

	// --force rotates: new pin, new key, meta rewritten.
	out3, err := captureStdout(t, func() error { return runKeygen([]string{"--out", keyPath, "--force"}) })
	if err != nil {
		t.Fatalf("keygen (force): %v", err)
	}
	if pin3 := parsePinLine(t, out3); pin3 == pin1 {
		t.Fatalf("--force did not rotate the key (pin unchanged: %q)", pin3)
	}
}

func TestDefaultKeyPath(t *testing.T) {
	got := defaultKeyPath()
	want := filepath.Join(".config", "quic-link", "key.pem")
	if !strings.HasSuffix(got, want) {
		t.Fatalf("defaultKeyPath() = %q, want suffix %q", got, want)
	}
}

// readMetaCreated parses the created = "..." RFC3339 value from a key.pem.meta
// sidecar without pulling in a TOML dependency.
func readMetaCreated(t *testing.T, path string) time.Time {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	line := strings.TrimSpace(string(data))
	first := strings.Index(line, "\"")
	last := strings.LastIndex(line, "\"")
	if first < 0 || last <= first {
		t.Fatalf("meta has no quoted created value: %q", line)
	}
	val := line[first+1 : last]
	ts, err := time.Parse(time.RFC3339, val)
	if err != nil {
		t.Fatalf("meta created is not RFC3339: %q: %v", val, err)
	}
	return ts
}
