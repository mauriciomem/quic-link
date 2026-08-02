package main

import (
	"strings"
	"testing"
)

// TestRouteListSet covers every documented error shape and success case for
// the --route NAME=ADDR repeatable flag.
func TestRouteListSet(t *testing.T) {
	cases := []struct {
		name       string
		values     []string // applied in order via Set
		wantErr    bool
		wantErrSub string // substring the final Set call's error must contain
	}{
		{"valid tcp", []string{"pg-app=tcp://127.0.0.1:5432"}, false, ""},
		{"valid unix", []string{"docker2=unix:///var/run/docker2.sock"}, false, ""},
		{"multiple distinct names", []string{"pg-app=tcp://127.0.0.1:5432", "pg-app2=tcp://127.0.0.1:5433"}, false, ""},

		{"no equals sign", []string{"pg-app"}, true, "expected NAME=ADDR"},
		{"empty name", []string{"=tcp://127.0.0.1:5432"}, true, "route name must not be empty"},
		{"empty address", []string{"pg-app="}, true, "route address must not be empty"},
		{"bad address scheme", []string{"pg-app=http://127.0.0.1:5432"}, true, "unsupported address scheme"},
		{"bad name", []string{"pg:app=tcp://127.0.0.1:5432"}, true, "must contain only letters"},
		{"duplicate name", []string{"ssh=tcp://127.0.0.1:22", "ssh=tcp://127.0.0.1:2222"}, true, "duplicate --route"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r routeList
			var err error
			for _, v := range tc.values {
				err = r.Set(v)
				if err != nil {
					break
				}
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Set(%v): want error, got nil", tc.values)
				}
				if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("Set(%v) error = %q, want substring %q", tc.values, err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set(%v): unexpected error: %v", tc.values, err)
			}
		})
	}
}

// TestRouteListSetPopulatesMap verifies the parsed NAME=ADDR pairs land in
// the map exactly as given, with no reformatting.
func TestRouteListSetPopulatesMap(t *testing.T) {
	var r routeList
	if err := r.Set("pg-app=tcp://127.0.0.1:5432"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := r.Set("docker2=unix:///var/run/docker2.sock"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, want := r.values["pg-app"], "tcp://127.0.0.1:5432"; got != want {
		t.Errorf("values[pg-app] = %q, want %q", got, want)
	}
	if got, want := r.values["docker2"], "unix:///var/run/docker2.sock"; got != want {
		t.Errorf("values[docker2] = %q, want %q", got, want)
	}
}

// TestRouteListDuplicateErrorNamesBothValues verifies the duplicate error
// message names the route and the value it was already set to.
func TestRouteListDuplicateErrorNamesBothValues(t *testing.T) {
	var r routeList
	if err := r.Set("ssh=tcp://127.0.0.1:22"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	err := r.Set("ssh=tcp://127.0.0.1:2222")
	if err == nil {
		t.Fatal("want error for duplicate route name")
	}
	if !strings.Contains(err.Error(), `"ssh"`) || !strings.Contains(err.Error(), "tcp://127.0.0.1:22") {
		t.Errorf("duplicate error should name the route and its existing value, got: %v", err)
	}
}
