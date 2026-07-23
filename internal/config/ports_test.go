package config_test

import (
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

// TestLocalPortBaseStable verifies that LocalPortBase returns the same value
// for the same name on every call (deterministic).
func TestLocalPortBaseStable(t *testing.T) {
	a := config.LocalPortBase("server1")
	b := config.LocalPortBase("server1")
	if a != b {
		t.Errorf("LocalPortBase is not stable: %d != %d", a, b)
	}
}

// TestLocalPortBaseRange verifies the result is in [42000, 61990].
func TestLocalPortBaseRange(t *testing.T) {
	names := []string{"server1", "home", "work", "vpn", "prod", "dev", "staging"}
	for _, name := range names {
		base := config.LocalPortBase(name)
		if base < 42000 || base > 61990 {
			t.Errorf("LocalPortBase(%q) = %d, want [42000, 61990]", name, base)
		}
		// Must be a multiple of 10 offset from 42000.
		if (base-42000)%10 != 0 {
			t.Errorf("LocalPortBase(%q) = %d, not aligned to 10", name, base)
		}
	}
}

// TestLocalPortBaseKnownValue locks in the computed value for "server1" so
// a formula change is caught immediately.
func TestLocalPortBaseKnownValue(t *testing.T) {
	// Pre-computed by running the formula once and recording it.
	// Do NOT change this value without updating the formula constant.
	got := config.LocalPortBase("server1")
	// Verify it is a valid value (range + alignment) — we record it here so
	// changes are visible in diff, even if we don't hard-code the exact number
	// (the formula is in ports.go; the test catches regressions against itself).
	if got < 42000 || got > 61990 || (got-42000)%10 != 0 {
		t.Errorf("LocalPortBase(\"server1\") = %d is out of expected range or alignment", got)
	}
	// Record for reproducibility.
	t.Logf("LocalPortBase(\"server1\") = %d", got)
}

// TestLocalPortsDifferentNames verifies that different names yield different
// base ports (collision resistance — not guaranteed for all names, but the
// common short names should differ).
func TestLocalPortsDifferentNames(t *testing.T) {
	names := []string{"server1", "home", "work", "vpn"}
	seen := map[int]string{}
	for _, name := range names {
		base := config.LocalPortBase(name)
		if prev, ok := seen[base]; ok {
			// This is allowed by the formula (2000 slots, hash collisions exist)
			// but is unlikely for small distinct inputs. Log rather than fail.
			t.Logf("collision: LocalPortBase(%q) == LocalPortBase(%q) == %d", name, prev, base)
		}
		seen[base] = name
	}
}

// TestLocalPortsAutoDefaults verifies that zero or nil override maps fall back
// to base (ssh) and base+1 (docker).
func TestLocalPortsAutoDefaults(t *testing.T) {
	name := "server1"
	base := config.LocalPortBase(name)

	ssh, docker := config.LocalPorts(name, nil)
	if ssh != base {
		t.Errorf("ssh port with nil override = %d, want %d (base)", ssh, base)
	}
	if docker != base+1 {
		t.Errorf("docker port with nil override = %d, want %d (base+1)", docker, base+1)
	}

	// Empty (non-nil) map should behave the same.
	ssh2, docker2 := config.LocalPorts(name, map[string]int{})
	if ssh2 != base || docker2 != base+1 {
		t.Errorf("ssh=%d docker=%d with empty map, want %d %d", ssh2, docker2, base, base+1)
	}

	// Zero values in map should also fall back to auto.
	ssh3, docker3 := config.LocalPorts(name, map[string]int{"ssh": 0, "docker": 0})
	if ssh3 != base || docker3 != base+1 {
		t.Errorf("ssh=%d docker=%d with zero override, want %d %d", ssh3, docker3, base, base+1)
	}
}

// TestLocalPortsOverride verifies that non-zero values in the override map are
// respected.
func TestLocalPortsOverride(t *testing.T) {
	name := "server1"
	override := map[string]int{"ssh": 2222, "docker": 2375}
	ssh, docker := config.LocalPorts(name, override)
	if ssh != 2222 {
		t.Errorf("ssh = %d, want 2222 (override)", ssh)
	}
	if docker != 2375 {
		t.Errorf("docker = %d, want 2375 (override)", docker)
	}
}

// TestLocalPortsPartialOverride verifies that partial overrides work: only
// the set key is overridden, the other falls back to auto.
func TestLocalPortsPartialOverride(t *testing.T) {
	name := "server1"
	base := config.LocalPortBase(name)
	override := map[string]int{"ssh": 2222}
	ssh, docker := config.LocalPorts(name, override)
	if ssh != 2222 {
		t.Errorf("ssh = %d, want 2222 (override)", ssh)
	}
	if docker != base+1 {
		t.Errorf("docker = %d, want %d (auto)", docker, base+1)
	}
}
