package router

import (
	"strings"
	"testing"
)

func TestValidateRouteName(t *testing.T) {
	sixtyFour := strings.Repeat("a", 64)
	sixtyFive := strings.Repeat("a", 65)

	cases := []struct {
		name    string
		route   string
		wantErr bool
	}{
		{"ssh", "ssh", false},
		{"docker", "docker", false},
		{"dash", "pg-app", false},
		{"underscore", "pg_app", false},
		{"dot", "pg.app", false},
		{"mixed case", "Route1", false},
		{"64 bytes", sixtyFour, false},

		{"empty", "", true},
		{"65 bytes", sixtyFive, true},
		{"colon", "pg:app", true},
		{"equals", "pg=app", true},
		{"space", "pg app", true},
		{"slash", "pg/app", true},
		{"newline", "pg\napp", true},
		{"non-ascii", "pgü", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRouteName(tc.route)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateRouteName(%q): want error, got nil", tc.route)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateRouteName(%q): unexpected error: %v", tc.route, err)
			}
		})
	}
}

// TestValidateRouteName_RejectsWildcards pins the fact that this validator has
// no notion of a wildcard label. It is recorded separately from the table above
// because it is the reason a hostname-matching table cannot simply reuse this
// function: a pattern like "*.foo.internal" is refused here, so a naive reuse
// would silently refuse every wildcard entry and quietly disable the feature
// that depends on them.
//
// If this test ever starts failing because "*" was added to the allowed set,
// that is a decision about route names, and it needs its own reasoning: route
// names are resolved by exact lookup, so a wildcard has no meaning for them.
func TestValidateRouteName_RejectsWildcards(t *testing.T) {
	for _, pattern := range []string{"*", "*.foo.internal", "*.internal", "foo.*"} {
		if err := ValidateRouteName(pattern); err == nil {
			t.Errorf("ValidateRouteName(%q): want error (no wildcard support), got nil", pattern)
		}
	}
}

// TestValidateRouteName_AcceptsAHostname pins the other half: a plain dotted
// hostname passes, because dots are allowed. A hostname-keyed table may
// therefore share the character rule while needing its own wildcard handling.
func TestValidateRouteName_AcceptsAHostname(t *testing.T) {
	for _, name := range []string{"grafana.server1.internal", "server1.internal", "a.b.c.d.e"} {
		if err := ValidateRouteName(name); err != nil {
			t.Errorf("ValidateRouteName(%q): unexpected error: %v", name, err)
		}
	}
}
