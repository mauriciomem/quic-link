package main

// route_e2e_test.go drives malformed and duplicate --route values through
// the actual cobra command line (executeRoot), rather than testing
// routeList.Set in isolation (route_flag_test.go) or mutual exclusion with
// otherwise-valid values (agent_route_test.go). This project has its own
// recorded lesson that cobra has two separate error paths and that the
// wiring between cobra and exitCodeForError is exactly where a bug lived
// before (see root.go's SetFlagErrorFunc and wrapArgs); a bad --route value
// is parsed by pflag itself (routeList implements pflag.Value), a code path
// distinct from both cobra.PositionalArgs validators and this codebase's own
// hand-written usageErrorf call sites, so it deserves its own end-to-end
// regression coverage rather than relying on the unit tests above to imply
// the wiring is correct.

import (
	"testing"
)

func TestAgentRouteFlag_EndToEnd_Exit2(t *testing.T) {
	unsetQLEnvForTest(t)
	pin := mustTestPin(t)

	cases := []struct {
		name  string
		route []string // one or more --route values, applied in order
	}{
		{"malformed: no equals sign", []string{"pg-app"}},
		{"bad route name: contains a colon", []string{"pg:app=tcp://127.0.0.1:5432"}},
		{"bad address: unsupported scheme", []string{"pg-app=http://127.0.0.1:5432"}},
		{"duplicate route name", []string{"ssh=tcp://127.0.0.1:22", "ssh=tcp://127.0.0.1:2222"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, `
schema = 1
`)
			args := []string{
				"--config", path, "agent",
				"--listen", "127.0.0.1:0",
				"--authorized-client", pin,
			}
			for _, r := range tc.route {
				args = append(args, "--route", r)
			}
			err := runVerb(args)
			if err == nil {
				t.Fatal("expected an error for a malformed/duplicate --route, got nil")
			}
			if got := exitCode(err); got != 2 {
				t.Errorf("exitCode = %d, want 2 (usage error), err=%v", got, err)
			}
		})
	}
}
