package names_test

import (
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/names"
)

// mustZone builds a zone the tests expect to be buildable. A refusal here is a
// failure of the test's own fixture, so it stops that test rather than being
// carried into an assertion about something else.
func mustZone(t *testing.T, suffix string, servers []string) *names.Zone {
	t.Helper()
	z, err := names.NewZone(suffix, servers)
	if err != nil {
		t.Fatalf("NewZone(%q, %v): %v", suffix, servers, err)
	}
	return z
}

func TestZone_InSuffixIsAnchoredAtALabel(t *testing.T) {
	z := mustZone(t, "internal", []string{"server1"})
	cases := []struct {
		host string
		want bool
	}{
		{"internal", true},
		{"server1.internal", true},
		{"grafana.server1.internal", true},
		{"a.b.c.internal", true},

		{"notinternal", false},
		{"myinternal", false},
		{"internal.evil.example", false},
		{"xinternal", false},
		{"", false},
		{"internalx", false},
	}
	for _, tc := range cases {
		if got := z.InSuffix(tc.host); got != tc.want {
			t.Errorf("InSuffix(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestZone_Split(t *testing.T) {
	z := mustZone(t, "internal", []string{"server1"})
	cases := []struct {
		host            string
		server, service string
		ok              bool
	}{
		{"server1.internal", "server1", "", true},
		{"grafana.server1.internal", "server1", "grafana", true},
		{"a.b.server1.internal", "server1", "a.b", true},

		{"internal", "", "", false},
		{".internal", "", "", false},
		{"evil.example", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		server, service, ok := z.Split(tc.host)
		if ok != tc.ok || server != tc.server || service != tc.service {
			t.Errorf("Split(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.host, server, service, ok, tc.server, tc.service, tc.ok)
		}
	}
}

func TestZone_NormalisesItsInputs(t *testing.T) {
	z := mustZone(t, "INTERNAL.", []string{"Server1"})
	if z.Suffix() != "internal" {
		t.Errorf("suffix = %q, want %q", z.Suffix(), "internal")
	}
	if !z.Manages("server1") {
		t.Error("a server name given in mixed case must still be managed")
	}
}

// TestNewZone_RefusesANameItCouldNotServe pins the loud refusal. A name that is
// not a legal hostname label used to be admitted, which produced the worst
// possible pair of answers: this machine said yes over DNS, handing back the
// loopback address, and then refused the very same name at the door — so a
// caller was sent somewhere and found nothing there, with nothing logged either
// side of it.
//
// The whole zone is refused rather than the one name, because a machine
// answering for some of its names and silently not others is harder to explain
// than one that will not start.
func TestNewZone_RefusesANameItCouldNotServe(t *testing.T) {
	// Case is not in this list on purpose. A hostname is compared without
	// regard to case, so a name given in the wrong one is normalised rather
	// than refused; configuration checking is where that gets its own words,
	// because there the file is the thing to correct. What cannot be fixed by
	// normalising — a character that can never appear in a label — is refused
	// here.
	for _, bad := range []string{
		"(flags)", "my_server", "my.server", "-lead", "trail-",
		"has space", "127.0.0.1", strings.Repeat("a", 64),
	} {
		if _, err := names.NewZone("internal", []string{"server1", bad}); err == nil {
			t.Errorf("a zone containing %q must be refused: it would resolve and then not serve", bad)
		}
	}
}

// TestNewZone_StillAcceptsWhatItCanServe is the other half: the refusal must not
// have swept up ordinary names, including one given in the wrong case, which the
// constructor has always been willing to normalise for a caller that skipped
// validation.
func TestNewZone_StillAcceptsWhatItCanServe(t *testing.T) {
	z, err := names.NewZone("internal", []string{"server1", "gpu-box", "a", "0", "Mixed"})
	if err != nil {
		t.Fatalf("ordinary names must be accepted: %v", err)
	}
	for _, want := range []string{"server1", "gpu-box", "a", "0", "mixed"} {
		if !z.Manages(want) {
			t.Errorf("zone should manage %q", want)
		}
	}
}

// TestNewZone_SkipsAnEmptyNameWithoutRefusing pins a deliberate difference: an
// empty entry is dropped rather than treated as a bad name, because it carries
// no name to complain about and refusing on it would turn a caller's empty slot
// into a machine that will not start.
func TestNewZone_SkipsAnEmptyNameWithoutRefusing(t *testing.T) {
	z, err := names.NewZone("internal", []string{"server1", ""})
	if err != nil {
		t.Fatalf("an empty entry must be skipped, not refused: %v", err)
	}
	if !z.Manages("server1") {
		t.Error("the real name must survive alongside an empty one")
	}
	if len(z.Servers()) != 1 {
		t.Errorf("Servers() = %v, want just the one real name", z.Servers())
	}
}
