package names_test

import (
	"testing"

	"github.com/mauriciomem/quic-link/internal/names"
)

func TestZone_InSuffixIsAnchoredAtALabel(t *testing.T) {
	z := names.NewZone("internal", []string{"server1"})
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
	z := names.NewZone("internal", []string{"server1"})
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
	z := names.NewZone("INTERNAL.", []string{"Server1"})
	if z.Suffix() != "internal" {
		t.Errorf("suffix = %q, want %q", z.Suffix(), "internal")
	}
	if !z.Manages("server1") {
		t.Error("a server name given in mixed case must still be managed")
	}
}
