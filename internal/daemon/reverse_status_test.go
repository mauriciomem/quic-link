package daemon_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/daemon"
)

// The "listening" state has been part of the status contract since the daemon
// gained its enum, but until reverse mode nothing ever produced it. This pins
// what it looks like on the wire, in a fixture of its own: the forward-mode
// golden stays exactly as it was, because adding a state that was already
// documented is not a change to the shape of anything that existed.

// TestStatusJSON_ReverseGoldenFile captures a fleet with one server of each
// kind: one we connect out to and one that waits to be connected to.
func TestStatusJSON_ReverseGoldenFile(t *testing.T) {
	clock := newFixedClock()
	states := []daemon.SessionState{
		{
			Name:       "forward",
			State:      "connected",
			Transport:  "dial",
			Since:      clock.Now(),
			SSHPort:    42000,
			DockerPort: 42001,
			// Deliberately the other family from the forward golden, so the two
			// goldens between them pin both words that can be reported.
			Path: "ipv6-direct",
		},
		{
			Name:      "reverse",
			State:     "listening",
			Transport: "listen",
			Since:     clock.Now(),
			// No ports and no path: nothing is bound and nothing has arrived
			// for a session that has no peer yet.
		},
	}

	keyCreated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	metaReader := func(string) (time.Time, bool, error) { return keyCreated, true, nil }

	provider := daemon.NewStatusProvider(
		&fakePool{states: states},
		minimalCfgWithKey("/fake/key.pem", 180),
		clock,
		metaReader,
	)
	got, err := provider.StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}

	golden := filepath.Join("testdata", "status_golden_reverse.json")
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
		t.Errorf("reverse-mode status bytes differ from golden\n\ngot:  %s\n\nwant: %s", got, want)
	}
}

// TestStatusJSON_ListeningUsesTheDocumentedFieldNames guards the two values a
// consumer keys off, independently of the byte-for-byte fixture, so a rename
// fails with a message about the rename rather than a diff of two long lines.
func TestStatusJSON_ListeningUsesTheDocumentedFieldNames(t *testing.T) {
	clock := newFixedClock()
	provider := daemon.NewStatusProvider(
		&fakePool{states: []daemon.SessionState{{
			Name:      "reverse",
			State:     "listening",
			Transport: "listen",
			Since:     clock.Now(),
		}}},
		minimalCfgWithKey("/fake/key.pem", 180),
		clock,
		func(string) (time.Time, bool, error) { return time.Time{}, false, nil },
	)
	raw, err := provider.StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}

	var snap struct {
		Servers []struct {
			Name      string `json:"name"`
			Session   string `json:"session"`
			Transport string `json:"transport"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(snap.Servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(snap.Servers))
	}
	if snap.Servers[0].Session != "listening" {
		t.Errorf("session = %q, want listening", snap.Servers[0].Session)
	}
	if snap.Servers[0].Transport != "listen" {
		t.Errorf("transport = %q, want listen", snap.Servers[0].Transport)
	}
}

// TestListenEntry_WarnsWhenNoPeerEverArrives covers the diagnostic for the one
// misconfiguration that is otherwise completely silent: both ends configured to
// wait. Nothing errors, nothing retries, and the status output looks like a
// healthy idle server forever, so the only way an operator learns is if this
// side says so. Driven by moving the clock rather than waiting out the real
// interval.
func TestListenEntry_WarnsWhenNoPeerEverArrives(t *testing.T) {
	buf := captureLogs(t)
	clock := newJumpClock()

	r := newReverseRigWithClock(t, clock)
	_ = r

	// Let the loop reach its wait, then move past the threshold.
	clock.waitForArms(t, 1, 5*time.Second)
	clock.Advance(2 * time.Hour)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "no agent has connected") {
			out := buf.String()
			if !strings.Contains(out, "exactly one end must be the one that connects") {
				t.Errorf("the warning should name the likely cause; got:\n%s", out)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("nothing was logged after waiting past the threshold with no peer; log was:\n%s", buf.String())
}

// TestListenEntry_NoWarningOncePeerHasConnected is the control: the diagnostic
// must depend on nothing having connected, not merely on time passing.
func TestListenEntry_NoWarningOncePeerHasConnected(t *testing.T) {
	buf := captureLogs(t)
	clock := newJumpClock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r := newReverseRigWithClock(t, clock)
	r.connectAgent(t, ctx)
	waitForPoolState(t, r.pool, "rev", "connected", 10*time.Second)

	clock.Advance(2 * time.Hour)
	time.Sleep(300 * time.Millisecond)

	if strings.Contains(buf.String(), "no agent has connected") {
		t.Errorf("warned about no peer after one had already connected; log was:\n%s", buf.String())
	}
}
