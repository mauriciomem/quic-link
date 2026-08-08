package main

import (
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
)

// TestAgentServeOpts_MutationOptInComesFromTheConfigFile follows the operator's
// decision from the file they wrote to the value the serving layer acts on.
//
// It is deliberately not built from a hand-made settings value. Carrying a new
// setting from a file down to the code that uses it is the step that is easy to
// leave half-finished, and a test that starts from an already-populated struct
// cannot notice when that step is missing: it would pass against a program that
// ignored the file entirely.
func TestAgentServeOpts_MutationOptInComesFromTheConfigFile(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"absent", "", false},
		{"explicitly off", "allow_remote_route_mutation = false", false},
		{"explicitly on", "allow_remote_route_mutation = true", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			unsetQLEnvForTest(t)
			path := writeTestConfig(t, `
schema = 1
[agent]
listen = "0.0.0.0:7443"
authorized_clients = ["`+mustTestPin(t)+`"]
`+c.line+`
`)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Agent.AllowRemoteRouteMutation; got != c.want {
				t.Fatalf("the loaded setting = %v, want %v", got, c.want)
			}
			opts := agentServeOpts(*cfg.Agent, cfg.Identity, "ownpin", time.Now())
			if got := opts.AllowRemoteRouteMutation; got != c.want {
				t.Errorf("the setting handed to the serving layer = %v, want %v — "+
					"the operator's decision is not reaching the code that acts on it", got, c.want)
			}
		})
	}
}
