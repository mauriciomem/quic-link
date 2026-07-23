package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// ---- helpers ----------------------------------------------------------------

// writeOldMeta writes a .meta sidecar with a creation time daysAgo days in the
// past. Used to simulate a key that has aged past a rotation threshold.
func writeOldMeta(t *testing.T, keyFile string, daysAgo int) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Duration(daysAgo) * 24 * time.Hour)
	if err := identity.WriteMeta(keyFile, past); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
}

// writeFreshMeta writes a .meta sidecar with the current time.
func writeFreshMeta(t *testing.T, keyFile string) {
	t.Helper()
	if err := identity.WriteMeta(keyFile, time.Now().UTC()); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
}

// captureWarnLog captures slog.Warn messages emitted during fn() by temporarily
// installing a test handler that records them.
func captureWarnLog(t *testing.T, fn func()) []string {
	t.Helper()
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	fn()
	var warns []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "WARN") {
			warns = append(warns, line)
		}
	}
	return warns
}

// ---- A. Own-key age warn / refuse -------------------------------------------

// TestCheckKeyAge_NoMeta verifies that an absent .meta file produces no warning
// and no error (unknown age is not an alarm).
func TestCheckKeyAge_NoMeta(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	// No WriteMeta call — the sidecar does not exist.

	idCfg := config.Identity{WarnKeyAgeDays: 90, RefuseOldKey: false}
	warns := captureWarnLog(t, func() {
		if err := checkKeyAge(keyFile, idCfg); err != nil {
			t.Fatalf("checkKeyAge with absent meta: %v", err)
		}
	})
	if len(warns) > 0 {
		t.Errorf("expected no warnings for absent meta, got: %v", warns)
	}
}

// TestCheckKeyAge_FreshKey verifies that a key created today produces no
// warning and no error.
func TestCheckKeyAge_FreshKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	writeFreshMeta(t, keyFile)

	idCfg := config.Identity{WarnKeyAgeDays: 90, RefuseOldKey: false}
	warns := captureWarnLog(t, func() {
		if err := checkKeyAge(keyFile, idCfg); err != nil {
			t.Fatalf("checkKeyAge with fresh key: %v", err)
		}
	})
	if len(warns) > 0 {
		t.Errorf("expected no warnings for fresh key, got: %v", warns)
	}
}

// TestCheckKeyAge_OverAgeWarn verifies that a key older than the threshold
// produces a WARN log and no error when refuse_old_key is false.
func TestCheckKeyAge_OverAgeWarn(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	writeOldMeta(t, keyFile, 200) // 200 days old, threshold is 90

	idCfg := config.Identity{WarnKeyAgeDays: 90, RefuseOldKey: false}
	var checkErr error
	warns := captureWarnLog(t, func() {
		checkErr = checkKeyAge(keyFile, idCfg)
	})
	if checkErr != nil {
		t.Fatalf("checkKeyAge with old key (warn-only): got error %v, want nil", checkErr)
	}
	if len(warns) == 0 {
		t.Error("expected a WARN log for over-age key, got none")
	}
	// The warning should name the key file.
	found := false
	for _, w := range warns {
		if strings.Contains(w, filepath.Base(keyFile)) || strings.Contains(w, "rotation") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("WARN log does not mention the key file or rotation: %v", warns)
	}
}

// TestCheckKeyAge_OverAgeRefuse verifies that refuse_old_key=true causes
// checkKeyAge to return a usage error (exit 2) for an over-age key.
func TestCheckKeyAge_OverAgeRefuse(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	writeOldMeta(t, keyFile, 200) // 200 days old, threshold is 90

	idCfg := config.Identity{WarnKeyAgeDays: 90, RefuseOldKey: true}
	err := checkKeyAge(keyFile, idCfg)
	if err == nil {
		t.Fatal("expected error for over-age key with refuse_old_key=true, got nil")
	}
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for refuse_old_key, got %d: %v", exitCode(err), err)
	}
}

// TestCheckKeyAge_WarnDisabled verifies that WarnKeyAgeDays=0 disables all
// age checks — no warning, no error, regardless of key age.
func TestCheckKeyAge_WarnDisabled(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	writeOldMeta(t, keyFile, 9999) // very old

	idCfg := config.Identity{WarnKeyAgeDays: 0, RefuseOldKey: true}
	warns := captureWarnLog(t, func() {
		if err := checkKeyAge(keyFile, idCfg); err != nil {
			t.Fatalf("checkKeyAge with WarnKeyAgeDays=0: %v", err)
		}
	})
	if len(warns) > 0 {
		t.Errorf("expected no warnings when threshold is 0, got: %v", warns)
	}
}

// TestAgentVerbRefuseOldKey exercises the full agent verb path via runVerb
// with a config that sets refuse_old_key = true and a key whose .meta reports
// an over-age creation date. Expects exit 2.
func TestAgentVerbRefuseOldKey(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Generate a key and then overwrite its .meta with a past date.
	keyPath := filepath.Join(tmp, "key.pem")
	if err := runVerb([]string{"keygen", "--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	writeOldMeta(t, keyPath, 200) // backdated past the 90-day threshold

	pin := mustTestPin(t)
	cfgPath := writeTestConfig(t, `
schema = 1
[identity]
key_file           = "`+keyPath+`"
warn_key_age_days  = 90
refuse_old_key     = true
[agent]
listen             = "127.0.0.1:0"
authorized_clients = ["`+pin+`"]
`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := runVerbCtx(ctx, []string{"--config", cfgPath, "agent"})
	if exitCode(err) != 2 {
		t.Errorf("expected exit 2 for refuse_old_key, got %d: %v", exitCode(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "days old") {
		t.Errorf("error should mention key age, got: %v", err)
	}
}

// TestAgentVerbWarnOldKeyNoRefuse verifies that warn_key_age_days without
// refuse_old_key logs a warning but does NOT abort — the agent starts (and we
// immediately cancel the context to avoid blocking the test).
func TestAgentVerbWarnOldKeyNoRefuse(t *testing.T) {
	unsetQLEnvForTest(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	keyPath := filepath.Join(tmp, "key.pem")
	if err := runVerb([]string{"keygen", "--out", keyPath}); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	writeOldMeta(t, keyPath, 200)

	pin := mustTestPin(t)
	cfgPath := writeTestConfig(t, `
schema = 1
[identity]
key_file           = "`+keyPath+`"
warn_key_age_days  = 90
refuse_old_key     = false
[agent]
listen             = "127.0.0.1:0"
authorized_clients = ["`+pin+`"]
`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately — we just want to verify it doesn't exit 2

	err := runVerbCtx(ctx, []string{"--config", cfgPath, "agent"})
	if exitCode(err) == 2 {
		t.Errorf("warn-only mode should not exit 2, got exit 2: %v", err)
	}
}

// TestReadKeyCreatedRFC3339 exercises the helper used by connect/ping to
// format the key creation time for the control stream.
func TestReadKeyCreatedRFC3339(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")

	t.Run("absent meta returns empty", func(t *testing.T) {
		if got := readKeyCreatedRFC3339(keyFile); got != "" {
			t.Errorf("absent .meta: got %q, want empty", got)
		}
	})

	now := time.Now().UTC().Truncate(time.Second)
	if err := identity.WriteMeta(keyFile, now); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}

	t.Run("present meta returns RFC3339", func(t *testing.T) {
		got := readKeyCreatedRFC3339(keyFile)
		if got == "" {
			t.Fatal("present .meta: got empty string, want RFC3339")
		}
		parsed, err := time.Parse(time.RFC3339, got)
		if err != nil {
			t.Fatalf("returned value is not RFC3339: %q: %v", got, err)
		}
		if !parsed.Equal(now) {
			t.Errorf("time mismatch: got %v, want %v", parsed, now)
		}
	})
}

// TestCheckKeyAge_ReadMetaError verifies that a malformed .meta file is
// handled gracefully (warning logged, no error returned from checkKeyAge).
func TestCheckKeyAge_ReadMetaError(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	// Write a malformed .meta (not TOML; WriteFile bypasses WriteMeta).
	if err := os.WriteFile(keyFile+".meta", []byte("not valid TOML {{{{"), 0o600); err != nil {
		t.Fatalf("write malformed meta: %v", err)
	}

	idCfg := config.Identity{WarnKeyAgeDays: 90, RefuseOldKey: true}
	// Should not return an error (graceful degradation, not a hard failure).
	if err := checkKeyAge(keyFile, idCfg); err != nil {
		t.Fatalf("checkKeyAge with malformed meta: expected nil, got %v", err)
	}
}
