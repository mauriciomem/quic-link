package main

// @spec-handoff
//
// Interface: no new production code — this asserts on the Long field of six
// existing cobra commands (vhosts, vhosts rm, status, ssh, docker-env,
// fwd), the same field status_help_test.go already reads via statusLongHelp.
//
// Behavior: each of these commands documents a SERVER-omission auto-select
// rule. The rule is implemented by autoSelectServer/knownServers
// (resolve_server.go), which asks the running daemon first and falls back to
// the config file — neither source is filtered by a server's Enabled field.
// The word "known" describes that; "enabled" does not, and every one of
// these six help strings currently says "enabled".
//
// status's --routes text additionally names three verbs as sharing this
// mechanism: "ssh"/"docker-env"/"connect". connect does not share it — it
// resolves through the distinct, Enabled-filtering enabledServers, never
// autoSelectServer — so status's text should name only the two verbs that do.
//
// Edge cases:
//   - vhosts rm is a subcommand, reached by descending one level from vhosts.
//   - the "disabled" runtime-refusal messages on these same verbs describe
//     the Enabled config field correctly and are untouched by this — nothing
//     here asserts on that wording.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// verbLongHelp walks the root command's tree by name and returns the found
// command's Long text, the same field a user reads under --help. path is
// one name for a top-level verb, or two names ("vhosts", "rm") to descend
// into a subcommand — vhosts rm is the only nested case this package's help
// text needs to reach.
func verbLongHelp(t *testing.T, path ...string) string {
	t.Helper()
	if len(path) == 0 {
		t.Fatal("verbLongHelp: no path given")
	}
	cmds := newRootCmd().Commands()
	var found *cobra.Command
	for depth, name := range path {
		found = nil
		for _, c := range cmds {
			if c.Name() == name {
				found = c
				break
			}
		}
		if found == nil {
			t.Fatalf("verb %q not found at depth %d of path %v", name, depth, path)
		}
		cmds = found.Commands()
	}
	return found.Long
}

// TestServerOmissionHelp_SaysKnown_NotEnabled pins the wording fix across
// every help string that documents autoSelectServer's SERVER-omission rule.
// The rule is checked against knownServers, not against any server's Enabled
// field, so "known" is the accurate word and "enabled" is not — regardless
// of which of these five files and six commands states it.
func TestServerOmissionHelp_SaysKnown_NotEnabled(t *testing.T) {
	cases := []struct {
		name     string
		path     []string
		wantHas  string
		wantNoth string
	}{
		{
			name:     "vhosts",
			path:     []string{"vhosts"},
			wantHas:  "when exactly one server is known",
			wantNoth: "when exactly one server is enabled",
		},
		{
			name:     "vhosts_rm",
			path:     []string{"vhosts", "rm"},
			wantHas:  "when exactly one server is known",
			wantNoth: "when exactly one server is enabled",
		},
		{
			name:     "ssh",
			path:     []string{"ssh"},
			wantHas:  "the sole known server",
			wantNoth: "the sole enabled server",
		},
		{
			name:     "docker_env",
			path:     []string{"docker-env"},
			wantHas:  "the sole known server",
			wantNoth: "the sole enabled server",
		},
		{
			name:     "fwd",
			path:     []string{"fwd"},
			wantHas:  "the sole known server",
			wantNoth: "the sole enabled server",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			help := verbLongHelp(t, tc.path...)
			if !strings.Contains(help, tc.wantHas) {
				t.Errorf("%s help does not say %q; it describes autoSelectServer's "+
					"known-server rule, not an Enabled check, so this is the accurate wording",
					strings.Join(tc.path, " "), tc.wantHas)
			}
			if strings.Contains(help, tc.wantNoth) {
				t.Errorf("%s help still says %q; autoSelectServer never filters on "+
					"Enabled, so this phrasing describes a check the code does not perform",
					strings.Join(tc.path, " "), tc.wantNoth)
			}
		})
	}
}

// TestStatusRoutesHelp_SaysKnown_NotEnabled pins the same word fix on
// status's --routes text.
func TestStatusRoutesHelp_SaysKnown_NotEnabled(t *testing.T) {
	help := verbLongHelp(t, "status")
	if !strings.Contains(help, "when exactly one server is known in config") {
		t.Error(`status help does not say "when exactly one server is known in config"; ` +
			"it describes autoSelectServer's known-server rule, not an Enabled check")
	}
	if strings.Contains(help, "enabled in config") {
		t.Error(`status help still says "enabled in config"; autoSelectServer never ` +
			"filters on Enabled, so this phrasing describes a check the code does not perform")
	}
}

// TestStatusRoutesHelp_DoesNotNameConnect pins the second, larger defect in
// the same sentence: it lists connect alongside ssh and docker-env as
// sharing the auto-selection mechanism it is describing. ssh and docker-env
// both call autoSelectServer; connect calls resolveConnectScope, which
// resolves through enabledServers — a different function that DOES filter
// on Enabled. Naming connect there misdescribes what connect does, not just
// which adjective is used, so the fix removes it rather than rewording it.
func TestStatusRoutesHelp_DoesNotNameConnect(t *testing.T) {
	help := verbLongHelp(t, "status")
	if strings.Contains(help, `"connect"`) {
		t.Error(`status help still names "connect" among the verbs sharing its ` +
			"auto-selection mechanism; connect resolves through enabledServers, not " +
			"autoSelectServer, so it does not share that mechanism")
	}
}
