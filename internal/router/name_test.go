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
