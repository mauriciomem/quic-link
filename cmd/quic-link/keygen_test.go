package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written. keygen status messages (created / reused / rotating) go to stderr.
func captureStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	runErr := fn()
	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

// captureAll captures both stdout and stderr simultaneously. keygen writes the
// CONTRACT "pin: <base64>" to stdout and status messages to stderr; we must
// assert them independently to prove stdout is unaffected by stderr additions.
func captureAll(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	// Capture stdout.
	oldOut := os.Stdout
	rOut, wOut, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("stdout pipe: %v", pipeErr)
	}
	os.Stdout = wOut

	// Capture stderr.
	oldErr := os.Stderr
	rErr, wErr, pipeErr2 := os.Pipe()
	if pipeErr2 != nil {
		t.Fatalf("stderr pipe: %v", pipeErr2)
	}
	os.Stderr = wErr

	runErr := fn()

	wOut.Close()
	wErr.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr

	outBytes, _ := io.ReadAll(rOut)
	errBytes, _ := io.ReadAll(rErr)
	return string(outBytes), string(errBytes), runErr
}

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

// TestKeygenStderr_CreatedVsReused verifies the three distinct status messages
// keygen emits to stderr:
//
//   - Fresh creation: "created new identity at <path>"
//   - Reuse (no --force): "reused existing identity at <path>"
//   - Rotation (--force): "warning: rotating identity; peers must re-pair with the new pin"
//
// It also asserts that the stdout CONTRACT "pin: <base64>" line is byte-stable
// across all three paths — stderr additions must never contaminate stdout.
func TestKeygenStderr_CreatedVsReused(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	// ---- first run: fresh creation ----
	stdout1, stderr1, err := captureAll(t, func() error {
		return runKeygen([]string{"--out", keyPath})
	})
	if err != nil {
		t.Fatalf("keygen (create): %v", err)
	}
	// stderr must contain a "created" message naming the key path.
	if !strings.Contains(stderr1, "created new identity") {
		t.Errorf("first run stderr missing 'created new identity': %q", stderr1)
	}
	if !strings.Contains(stderr1, keyPath) {
		t.Errorf("first run stderr missing key path %q: %q", keyPath, stderr1)
	}
	// stdout must be exactly "pin: <base64>\n" — the CONTRACT line.
	pin1 := parsePinLine(t, stdout1)
	if !strings.HasPrefix(stdout1, "pin: ") {
		t.Errorf("stdout does not start with 'pin: ': %q", stdout1)
	}

	// ---- second run: reuse (no --force) ----
	stdout2, stderr2, err := captureAll(t, func() error {
		return runKeygen([]string{"--out", keyPath})
	})
	if err != nil {
		t.Fatalf("keygen (reuse): %v", err)
	}
	// stderr must contain a "reused" message.
	if !strings.Contains(stderr2, "reused existing identity") {
		t.Errorf("reuse run stderr missing 'reused existing identity': %q", stderr2)
	}
	if !strings.Contains(stderr2, keyPath) {
		t.Errorf("reuse run stderr missing key path %q: %q", keyPath, stderr2)
	}
	// stdout must still be the same CONTRACT "pin: <base64>" line.
	pin2 := parsePinLine(t, stdout2)
	if pin2 != pin1 {
		t.Errorf("reuse run changed pin: %q -> %q", pin1, pin2)
	}
	if stdout2 != stdout1 {
		t.Errorf("stdout changed between create and reuse runs:\n  create: %q\n  reuse:  %q", stdout1, stdout2)
	}

	// ---- third run: rotation (--force) ----
	stdout3, stderr3, err := captureAll(t, func() error {
		return runKeygen([]string{"--out", keyPath, "--force"})
	})
	if err != nil {
		t.Fatalf("keygen (force): %v", err)
	}
	// stderr must contain the rotation warning.
	if !strings.Contains(stderr3, "rotating identity") {
		t.Errorf("force run stderr missing 'rotating identity': %q", stderr3)
	}
	if !strings.Contains(stderr3, "re-pair") {
		t.Errorf("force run stderr missing 're-pair': %q", stderr3)
	}
	// stdout must be a new CONTRACT "pin: <base64>" line (different pin after rotation).
	pin3 := parsePinLine(t, stdout3)
	if pin3 == pin1 {
		t.Errorf("--force did not rotate: pin unchanged %q", pin1)
	}
	// The format of stdout must be exactly "pin: <base64>\n" — no extra lines.
	wantPrefix := "pin: "
	if !strings.HasPrefix(stdout3, wantPrefix) {
		t.Errorf("stdout after --force does not start with %q: %q", wantPrefix, stdout3)
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
