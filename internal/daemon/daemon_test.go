package daemon_test

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/daemon"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

var update = flag.Bool("update", false, "regenerate golden files")

// ---- fakes for deterministic testing ----------------------------------------

// fixedClock is a Clock that always returns a fixed time.
type fixedClock struct {
	now time.Time
}

func newFixedClock() *fixedClock {
	return &fixedClock{
		now: time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
	}
}

func (c *fixedClock) Now() time.Time                  { return c.now }
func (c *fixedClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }
func (c *fixedClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	return ch
}

// fakePool implements SessionPool with fixed state for testing.
type fakePool struct {
	states []daemon.SessionState
}

func (p *fakePool) Get(_ context.Context, _ string) (daemon.Conn, error) {
	return nil, nil
}

func (p *fakePool) State() []daemon.SessionState {
	return p.states
}

func (p *fakePool) EntryState(server string) (string, error) {
	for _, s := range p.states {
		if s.Name == server {
			return s.State, nil
		}
	}
	return "", nil
}

// ControlCall is not exercised by this file's tests (they cover the status
// snapshot, not the control relay); it satisfies the interface with a clear
// refusal rather than silently succeeding against fabricated state.
func (p *fakePool) ControlCall(context.Context, string, func(context.Context, *control.Client) error) error {
	return fmt.Errorf("fakePool: ControlCall not implemented")
}

func (p *fakePool) Close() {}

// ---- TestStatusJSON_GoldenFile -----------------------------------------------

// TestStatusJSON_GoldenFile verifies that the bytes produced by the daemon's
// StatusProvider.StatusJSON() — the exact bytes the daemon emits over the IPC
// socket and that status --json prints to stdout — match the committed golden
// file byte-for-byte.
//
// The test goes through NewStatusProvider(...).StatusJSON() rather than
// json.MarshalIndent so it exercises the real emitted code path (compact JSON,
// no indentation). The golden stores compact JSON so it faithfully mirrors what
// a script consuming "quic-link status --json" actually receives.
//
// Secret-leakage guard: the golden carries no pin or key material. Any future
// field that adds a full 44-char pin or key bytes breaks the golden and forces
// a deliberate review. If a pin is ever surfaced it MUST be the 8-char prefix,
// never the full value.
func TestStatusJSON_GoldenFile(t *testing.T) {
	clock := newFixedClock()
	// since is set to clock.Now() so since_ms == 0 (zero duration from now).
	states := []daemon.SessionState{
		{
			Name:       "server1",
			State:      "connected",
			Transport:  "dial",
			Since:      clock.Now(),
			SSHPort:    42000,
			DockerPort: 42001,
			Path:       "ipv4-direct",
		},
		{
			Name:      "server2",
			State:     "disabled",
			Transport: "dial",
			Since:     clock.Now(),
			// SSHPort and DockerPort are 0: a disabled server has no listeners.
			// The golden captures this as {"ssh":0,"docker":0}. Path is left
			// unset for the same reason, and the golden captures its absence:
			// nothing was ever attempted, so there is no route to name.
		},
	}

	// Key created on 2026-01-01, one day before the fixed "now" (2026-01-02).
	// clock.Since(keyCreated) ≈ 1.63 days → age_days = 1.
	keyCreated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	metaReader := func(string) (time.Time, bool, error) {
		return keyCreated, true, nil
	}

	// Build the snapshot through the same provider the daemon wires in Run,
	// using a minimal config carrying only the fields StatusJSON reads.
	cfg := minimalCfgWithKey("/fake/key.pem", 180)
	provider := daemon.NewStatusProvider(
		&fakePool{states: states},
		cfg,
		clock,
		metaReader,
	)
	got, err := provider.StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}

	// Cross-check: direct json.Marshal of the same snapshot must produce the
	// same bytes, confirming the provider uses compact (not indented) encoding.
	snap := daemon.BuildSnapshot(states, clock, "/fake/key.pem", 180, metaReader)
	directMarshal, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != string(directMarshal) {
		t.Errorf("StatusJSON() bytes differ from json.Marshal(snap):\n  StatusJSON: %s\n  Marshal:    %s",
			got, directMarshal)
	}

	golden := filepath.Join("testdata", "status_golden.json")

	if *update {
		if err := os.MkdirAll("testdata", 0o700); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden file updated: %s", golden)
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to generate): %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("status --json emitted bytes differ from golden; "+
			"if intentional, bump schema and run with -update\n\ngot:  %s\n\nwant: %s",
			got, want)
	}
}

// TestStatusJSON_IdentityOmittedWhenMetaAbsent verifies that the identity block
// is omitted when the .meta sidecar is absent, preventing false rotation alarms.
func TestStatusJSON_IdentityOmittedWhenMetaAbsent(t *testing.T) {
	clock := newFixedClock()
	states := []daemon.SessionState{
		{
			Name:       "server1",
			State:      "connected",
			Transport:  "dial",
			Since:      clock.Now(),
			SSHPort:    42000,
			DockerPort: 42001,
		},
	}

	// Absent sidecar: present=false.
	metaReader := func(path string) (time.Time, bool, error) {
		return time.Time{}, false, nil
	}

	snap := daemon.BuildSnapshot(states, clock, "/fake/key.pem", 180, metaReader)

	if snap.Identity != nil {
		t.Errorf("identity block present when .meta sidecar is absent; want nil")
	}

	// Verify the JSON marshals with identity omitted.
	got, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := obj["identity"]; ok {
		t.Errorf("identity key present in JSON output when sidecar absent")
	}
}

// minimalCfgWithKey returns a config.Config whose Identity fields match what
// snapshotProvider.StatusJSON reads: the key file path and the warn-age-days
// threshold. All other fields are left at defaults. The daemon does not read
// the key file itself in the status path; the meta sidecar reader is injected.
func minimalCfgWithKey(keyFile string, warnKeyAgeDays int) *config.Config {
	cfg := config.Defaults()
	cfg.Identity.KeyFile = keyFile
	cfg.Identity.WarnKeyAgeDays = warnKeyAgeDays
	return cfg
}

// TestBuildSnapshot_ConnectedAndDisabled verifies three of the five enum values
// are produced correctly from the fake pool state.
func TestBuildSnapshot_ConnectedAndDisabled(t *testing.T) {
	clock := newFixedClock()
	states := []daemon.SessionState{
		{Name: "s1", State: "connected", Transport: "dial", Since: clock.Now()},
		{Name: "s2", State: "disabled", Transport: "dial", Since: clock.Now()},
		{Name: "s3", State: "connecting", Transport: "dial", Since: clock.Now()},
	}
	metaReader := func(string) (time.Time, bool, error) { return time.Time{}, false, nil }

	snap := daemon.BuildSnapshot(states, clock, "", 0, metaReader)

	if len(snap.Servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(snap.Servers))
	}
	for i, want := range []string{"connected", "disabled", "connecting"} {
		if got := snap.Servers[i].Session; got != want {
			t.Errorf("server[%d].session = %q, want %q", i, got, want)
		}
	}
}
