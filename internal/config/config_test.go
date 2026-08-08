package config_test

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// ---- helpers ----------------------------------------------------------------

// writeConfig writes content to a file in a temp directory and returns the path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// mustPin generates a fresh Ed25519 key and returns its canonical pin.
func mustPin(t *testing.T) string {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	return pin
}

// unsetEnv removes a variable for the test and restores it afterwards.
func setEnv(t *testing.T, key, val string) {
	t.Helper()
	old, hadOld := os.LookupEnv(key)
	if err := os.Setenv(key, val); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	t.Cleanup(func() {
		if hadOld {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// unsetAllQLEnv removes all QUIC_LINK_* variables for the duration of a test
// so prior env state doesn't bleed in.
func unsetAllQLEnv(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(k, "QUIC_LINK_") {
			old := os.Getenv(k)
			_ = os.Unsetenv(k)
			kCopy := k
			t.Cleanup(func() { _ = os.Setenv(kCopy, old) })
		}
	}
}

// ---- reference configs (the three shapes from the schema reference examples) -----

// TestForwardClientConfig verifies the client forward-mode reference config
// from the schema docs: [servers.server1] with addr + pin.
func TestForwardClientConfig(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.server1]
addr = "home.example.net:7443"
pin  = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Schema != 1 {
		t.Errorf("schema = %d, want 1", cfg.Schema)
	}
	srv, ok := cfg.Servers["server1"]
	if !ok {
		t.Fatal("servers.server1 not found")
	}
	if srv.Addr != "home.example.net:7443" {
		t.Errorf("addr = %q, want home.example.net:7443", srv.Addr)
	}
	if srv.Pin != pin {
		t.Errorf("pin mismatch")
	}

	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

// TestReverseAgentConfig verifies the reverse-agent reference config:
// [agent] with dial= and authorized_clients.
func TestReverseAgentConfig(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[identity]
key_file = "/etc/quic-link/key.pem"
[agent]
dial = "workstation.example:7443"
authorized_clients = ["`+pin+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent == nil {
		t.Fatal("agent block not parsed")
	}
	if cfg.Agent.Dial != "workstation.example:7443" {
		t.Errorf("dial = %q", cfg.Agent.Dial)
	}
	if len(cfg.Agent.AuthorizedClients) != 1 {
		t.Fatalf("authorized_clients len=%d", len(cfg.Agent.AuthorizedClients))
	}

	warnings, err := cfg.Validate(config.RoleAgent)
	if err != nil {
		t.Fatalf("Validate(RoleAgent): %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

// TestReverseWorkstationConfig verifies the reverse-workstation reference
// config: [servers.server1] with listen= + pin (no addr).
func TestReverseWorkstationConfig(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.server1]
listen = ":7443"
pin    = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv := cfg.Servers["server1"]
	if srv.Listen != ":7443" {
		t.Errorf("listen = %q", srv.Listen)
	}

	// Reverse mode (listen set, addr empty) must not be flagged as an error.
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient) on reverse-workstation config: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

// TestForwardAgentConfig verifies the forward-listen agent config.
func TestForwardAgentConfig(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+pin+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleAgent)
	if err != nil {
		t.Fatalf("Validate(RoleAgent): %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

// ---- unknown key errors -----------------------------------------------------

// TestUnknownTopLevelTable verifies that a typo in a top-level table name
// (e.g. [naming] instead of [names]) is rejected with an error that:
//   - wraps ErrInvalid
//   - mentions the offending key
//   - mentions the doc path
func TestUnknownTopLevelTable(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[naming]
suffix = "internal"
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for unknown top-level table [naming], got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "naming") {
		t.Errorf("error %q does not mention the offending key 'naming'", err.Error())
	}
	if !strings.Contains(err.Error(), "docs/configuration.md") {
		t.Errorf("error %q does not mention the public doc path", err.Error())
	}
	if strings.Contains(err.Error(), "internal-docs") {
		t.Errorf("error %q references internal-docs, which is gitignored and unreadable by a public user: %s", err.Error(), err.Error())
	}
}

// TestUnknownAgentKey verifies that a typo in [agent] (e.g. autohrized_clients)
// is rejected with an error mentioning the offending key and the doc path.
func TestUnknownAgentKey(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
autohrized_clients = []
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for unknown agent key, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "autohrized_clients") {
		t.Errorf("error %q does not mention 'autohrized_clients'", err.Error())
	}
	if !strings.Contains(err.Error(), "docs/configuration.md") {
		t.Errorf("error %q does not mention the public doc path", err.Error())
	}
	if strings.Contains(err.Error(), "internal-docs") {
		t.Errorf("error %q references internal-docs, which is gitignored and unreadable by a public user: %s", err.Error(), err.Error())
	}
}

// ---- addr/listen mutual exclusion -------------------------------------------

// TestAddrAndListenBothSet verifies that setting both addr and listen on a
// server entry yields a hard error under RoleClient, naming the server.
func TestAddrAndListenBothSet(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.myserver]
addr   = "1.2.3.4:7443"
listen = ":7443"
pin    = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v (unexpected load error)", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected error for addr+listen both set, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "myserver") {
		t.Errorf("error %q does not name the server", err.Error())
	}
}

// TestNeitherAddrNorListenSet verifies that a server with neither addr nor
// listen yields a hard error under RoleClient naming the server.
func TestNeitherAddrNorListenSet(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.noaddr]
pin = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected error for neither addr nor listen set")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "noaddr") {
		t.Errorf("error %q does not name the server 'noaddr'", err.Error())
	}
}

// ---- authorized_clients empty -----------------------------------------------

// TestEmptyAuthorizedClientsAgentRole verifies that an [agent] block with an
// empty authorized_clients slice is a hard error under RoleAgent (never
// downgraded).
func TestEmptyAuthorizedClientsAgentRole(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = []
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatal("expected hard error for empty authorized_clients under RoleAgent")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestEmptyAuthorizedClientsClientRole verifies that the same [agent] config
// with empty authorized_clients is a WARNING (not an error) under RoleClient,
// because the agent section is inactive.
func TestEmptyAuthorizedClientsClientRole(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
[agent]
listen = ":7443"
authorized_clients = []
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): unexpected error %v", err)
	}
	// The empty authorized_clients problem should appear as a warning.
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "authorized_clients") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about authorized_clients but got warnings: %v", warnings)
	}
}

// ---- invalid pins -----------------------------------------------------------

// TestInvalidServerPin verifies that an invalid pin in [servers.<name>] is
// rejected as a hard error under the owning active role.
func TestInvalidServerPin(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[servers.bad]
addr = "1.2.3.4:7443"
pin  = "not-base64!!"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected error for invalid pin, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestInvalidAuthorizedClientPin verifies that an invalid pin in
// authorized_clients is a hard error under RoleAgent.
func TestInvalidAuthorizedClientPin(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["definitely-not-a-pin"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatal("expected error for invalid authorized_clients pin, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// ---- route validation -------------------------------------------------------

// TestBadRouteScheme verifies that a route with an unsupported scheme
// (e.g. postgres = "http://x") is a hard error under RoleAgent.
func TestBadRouteScheme(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+pin+`"]
[agent.routes]
postgres = "http://127.0.0.1:5432"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatal("expected error for unsupported route scheme, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestValidRoutes verifies that tcp:// and unix:// route addresses are
// accepted without error.
func TestValidRoutes(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+pin+`"]
[agent.routes]
postgres = "tcp://127.0.0.1:5432"
docker   = "unix:///var/run/docker.sock"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err != nil {
		t.Fatalf("Validate(RoleAgent): unexpected error %v", err)
	}
}

// TestBadRouteNameHardError verifies that a route name violating the shared
// naming rule (letters/digits/dash/underscore/dot, <=64 bytes) is a hard
// error under the agent role, wrapping ErrInvalid so it exits 2 rather than
// only being caught later inside router.New (which would exit 1).
func TestBadRouteNameHardError(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+pin+`"]
[agent.routes]
"pg:app" = "tcp://127.0.0.1:5432"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatal("expected error for invalid route name, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestBadRouteNameIsWarningUnderClientRole verifies the converse: the same
// bad route name is a warning, not a hard error, when the active role is
// client (the agent block is present but inactive).
func TestBadRouteNameIsWarningUnderClientRole(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
[agent]
listen = ":7443"
authorized_clients = ["`+pin+`"]
[agent.routes]
"pg:app" = "tcp://127.0.0.1:5432"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): unexpected hard error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "pg:app") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about invalid route name pg:app, got warnings: %v", warnings)
	}
}

// ---- precedence matrix ------------------------------------------------------

// TestPrecedenceDefaultLessThanFileLessThanEnv verifies the ordering:
// built-in default < file < environment variable.
//
//	log.level: default=info, file sets warn, env sets debug → expect debug.
func TestPrecedenceDefaultLessThanFileLessThanEnv(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[log]
level = "warn"
`)
	setEnv(t, "QUIC_LINK_LOG_LEVEL", "debug")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level = %q, want debug (env should win over file)", cfg.Log.Level)
	}
}

// TestPrecedenceFileBetterThanDefault verifies file > default without env.
func TestPrecedenceFileBetterThanDefault(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[log]
level = "warn"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("log.level = %q, want warn (file should win over default)", cfg.Log.Level)
	}
}

// TestEnvBadInt verifies that a non-integer value for an integer env var
// (QUIC_LINK_IDENTITY_WARN_KEY_AGE_DAYS) returns an error wrapping ErrInvalid.
func TestEnvBadInt(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `schema = 1`)
	setEnv(t, "QUIC_LINK_IDENTITY_WARN_KEY_AGE_DAYS", "abc")

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for non-integer WARN_KEY_AGE_DAYS, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestEnvAgentListen verifies that QUIC_LINK_AGENT_LISTEN allocates the Agent
// block when it was nil.
func TestEnvAgentListen(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `schema = 1`)
	setEnv(t, "QUIC_LINK_AGENT_LISTEN", ":9000")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent == nil {
		t.Fatal("Agent block should have been allocated by env var")
	}
	if cfg.Agent.Listen != ":9000" {
		t.Errorf("agent.listen = %q, want :9000", cfg.Agent.Listen)
	}
}

// ---- schema version ---------------------------------------------------------

// TestSchemaAbsent verifies that an absent schema field is treated as 1.
func TestSchemaAbsent(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `[log]
level = "info"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Schema != 1 {
		t.Errorf("schema = %d, want 1 (absent should default to 1)", cfg.Schema)
	}
}

// TestSchemaUnsupported verifies that schema = 2 (or any value other than 1)
// returns an error wrapping ErrInvalid.
func TestSchemaUnsupported(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `schema = 2`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for schema=2, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error %q does not mention schema value 2", err.Error())
	}
}

// ---- missing file handling --------------------------------------------------

// TestMissingDefaultFile verifies that when path="" and the default file does
// not exist, Load returns defaults with no error.
func TestMissingDefaultFile(t *testing.T) {
	unsetAllQLEnv(t)
	// Point the default location at a temp dir where no config.toml exists.
	// We cannot override the resolved default path, so we just call with path=""
	// and accept that on a dev machine the real ~/.config/quic-link/config.toml
	// might exist. Use a different approach: set HOME to a temp dir so the
	// default path resolves to a location that definitely has no config.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load with missing default file: %v", err)
	}
	// Should have the built-in defaults.
	if cfg.Log.Level != "info" {
		t.Errorf("log.level = %q, want info (default)", cfg.Log.Level)
	}
	if cfg.Identity.WarnKeyAgeDays != 180 {
		t.Errorf("warn_key_age_days = %d, want 180 (default)", cfg.Identity.WarnKeyAgeDays)
	}
}

// TestExplicitMissingFile verifies that an explicitly provided path that does
// not exist is an error (wrapping ErrInvalid).
func TestExplicitMissingFile(t *testing.T) {
	unsetAllQLEnv(t)
	_, err := config.Load("/does/not/exist/config.toml")
	if err == nil {
		t.Fatal("expected error for explicit missing file, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// ---- reserved tables parse without error ------------------------------------

// TestReservedTablesParse verifies that [names] parses cleanly under strict
// decoding, and that the two keys which used to sit beside it no longer do.
//
// This test used to assert the opposite. It accepted the exact config below,
// including [ports] and names.block, on the stated grounds that both were
// reserved for a future release and a forward-looking file must not be
// rejected. That future arrived and went a different way: nothing binds a
// privileged port, so there are no port modes, and nothing allocates addresses,
// so there is no block to reserve. Both keys are now refused with an
// explanation.
//
// The reversal is written out here rather than made by deleting the old test,
// because a documented promise being withdrawn should be visible to whoever
// reads this file next.
func TestReservedTablesParse(t *testing.T) {
	unsetAllQLEnv(t)

	// What [names] looks like now: accepted.
	path := writeConfig(t, `
schema = 1
[names]
suffix     = "internal"
dns_port   = 15353
http_port  = 18080
https_port = 18443
`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("Load with the current [names] table: %v", err)
	}

	// What it used to look like: refused, with a reason rather than a shrug.
	for _, removed := range []string{
		"[names]\nblock = \"127.42.0.0/16\"\n",
		"[ports]\nmode = \"auto\"\n",
	} {
		old := writeConfig(t, "schema = 1\n"+removed)
		_, err := config.Load(old)
		if err == nil {
			t.Fatalf("a key that was removed must be refused, not accepted: %q", removed)
		}
		if !strings.Contains(err.Error(), "no longer used") {
			t.Fatalf("refusal should explain the key was removed; got: %v", err)
		}
	}
}

// ---- tilde expansion --------------------------------------------------------

// TestTildeExpansionInKeyFile verifies that a leading ~ in identity.key_file
// is expanded to an absolute path after Load.
func TestTildeExpansionInKeyFile(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[identity]
key_file = "~/mykey.pem"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if strings.HasPrefix(cfg.Identity.KeyFile, "~") {
		t.Errorf("key_file not expanded: %q", cfg.Identity.KeyFile)
	}
	if !strings.HasSuffix(cfg.Identity.KeyFile, "mykey.pem") {
		t.Errorf("key_file = %q, expected suffix mykey.pem", cfg.Identity.KeyFile)
	}
}

// ---- severity / role switching ----------------------------------------------

// TestAgentProblemsAreWarningsUnderClientRole verifies that when the [agent]
// block has a problem (both listen and dial set) but the active role is client,
// the problem is a warning rather than an error.
func TestAgentProblemsAreWarningsUnderClientRole(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
[agent]
listen = ":7443"
dial   = "host:7443"
authorized_clients = ["`+pin+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): unexpected hard error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "mutually exclusive") || strings.Contains(w, "listen and dial") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about listen+dial on agent, got warnings: %v", warnings)
	}
}

// TestServerProblemsAreWarningsUnderAgentRole verifies the converse: a server
// entry problem is a warning (not an error) when the active role is agent.
func TestServerProblemsAreWarningsUnderAgentRole(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	// server1 has neither addr nor listen — that's a problem for a client but
	// only a warning for the agent role.
	path := writeConfig(t, `
schema = 1
[servers.s1]
pin = "`+pin+`"
[agent]
listen = ":7443"
authorized_clients = ["`+pin+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleAgent)
	if err != nil {
		t.Fatalf("Validate(RoleAgent): unexpected hard error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "s1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about server s1, got warnings: %v", warnings)
	}
}

// ---- ErrInvalid sentinel check ----------------------------------------------

// TestErrInvalidIsDistinct verifies that ErrInvalid is a distinct sentinel,
// not a generic errors.New, so callers can do reliable errors.Is matching.
func TestErrInvalidIsDistinct(t *testing.T) {
	if config.ErrInvalid == nil {
		t.Fatal("ErrInvalid must not be nil")
	}
	other := errors.New("other error")
	if errors.Is(other, config.ErrInvalid) {
		t.Fatal("an unrelated error should not match ErrInvalid")
	}

	// A real config error must match.
	wrapped := errors.New("some: invalid configuration") // not a real wrap
	if errors.Is(wrapped, config.ErrInvalid) {
		t.Fatal("a non-wrapped error message should not match ErrInvalid")
	}
	// Properly wrapped must match.
	_, err := config.Load("/does/not/exist/config.toml")
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("real load error does not wrap ErrInvalid: %v", err)
	}
}

// ---- Defaults() completeness check ------------------------------------------

// TestDefaults verifies the documented default values are present.
func TestDefaults(t *testing.T) {
	d := config.Defaults()
	if d.Log.Level != "info" {
		t.Errorf("default log.level = %q, want info", d.Log.Level)
	}
	if d.Log.Format != "text" {
		t.Errorf("default log.format = %q, want text", d.Log.Format)
	}
	if d.Identity.WarnKeyAgeDays != 180 {
		t.Errorf("default warn_key_age_days = %d, want 180", d.Identity.WarnKeyAgeDays)
	}
	if d.Identity.RefuseOldKey {
		t.Error("default refuse_old_key should be false")
	}
	if !strings.HasSuffix(d.Identity.KeyFile, filepath.Join(".config", "quic-link", "key.pem")) {
		t.Errorf("default key_file %q does not have expected suffix", d.Identity.KeyFile)
	}
}

// ---- server Enabled pointer -----------------------------------------------------------------

// TestServerEnabledDefault verifies that a server parsed without explicit
// "enabled" has a nil Enabled pointer (the default-true is applied by the caller).
func TestServerEnabledDefault(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Servers["s1"].Enabled != nil {
		t.Error("Enabled should be nil when not set in file (default-true is caller's job)")
	}
}

func TestServerEnabledExplicitFalse(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr    = "1.2.3.4:7443"
pin     = "`+pin+`"
enabled = false
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Servers["s1"].Enabled == nil {
		t.Fatal("Enabled should be non-nil when explicitly set")
	}
	if *cfg.Servers["s1"].Enabled {
		t.Error("Enabled should be false when explicitly set to false")
	}
}

// ---- type error in file ------------------------------------------------------

// TestTypeError verifies that a wrong type in the file (e.g. schema = "one")
// returns an error wrapping ErrInvalid with position information.
func TestTypeError(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `schema = "not-an-int"`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected type error for schema = \"not-an-int\", got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("type error does not wrap ErrInvalid: %v", err)
	}
}

// ---- disabled server severity -----------------------------------------------

// TestDisabledServerBadPinIsWarning verifies that an invalid pin on a server
// with enabled=false is demoted to a warning (not a hard error) under
// RoleClient, because a disabled server is not selectable.
func TestDisabledServerBadPinIsWarning(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[servers.broken]
addr    = "1.2.3.4:7443"
pin     = "not-base64!!"
enabled = false
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): expected no hard error for disabled server, got: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "broken") && strings.Contains(w, "disabled") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning mentioning 'broken' and 'disabled', got: %v", warnings)
	}
}

// TestDisabledServerBadPinEnabledIsError verifies that the same invalid pin is
// still a hard error when enabled is NOT false (nil or explicitly true), because
// that server is on the active path.
func TestDisabledServerBadPinEnabledIsError(t *testing.T) {
	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[servers.broken]
addr = "1.2.3.4:7443"
pin  = "not-base64!!"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected hard error for enabled server with bad pin, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestMixedEnabledDisabled verifies that one valid enabled server and one
// disabled server with a bad pin together yield no hard error but one warning.
func TestMixedEnabledDisabled(t *testing.T) {
	unsetAllQLEnv(t)
	good := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.good]
addr = "1.2.3.4:7443"
pin  = "`+good+`"

[servers.bad]
addr    = "5.6.7.8:7443"
pin     = "not-base64!!"
enabled = false
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): unexpected hard error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "bad") && strings.Contains(w, "disabled") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning about disabled server 'bad', got: %v", warnings)
	}
}

// ---- valid 32-byte pin: quick smoke -----------------------------------------

// TestValidPin32Bytes verifies that a freshly-generated pin (which is 32 bytes
// base64-encoded) is accepted by Validate via the pin-checking path.
func TestValidPin32Bytes(t *testing.T) {
	// A valid 32-byte all-zeros pin.
	zeros := make([]byte, 32)
	pin := base64.StdEncoding.EncodeToString(zeros)

	unsetAllQLEnv(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): %v", err)
	}
}

// ---- remote route mutation opt-in -------------------------------------------

// agentWithMutationKey builds a valid agent-role config, optionally carrying
// the opt-in line. The three states — absent, explicitly false, explicitly
// true — are separate cases because they are separate paths through the
// decoder: the first leaves the field at its zero value, the other two have
// the decoder visit and assign it.
func agentWithMutationKey(t *testing.T, line string) string {
	t.Helper()
	return writeConfig(t, `
schema = 1
[agent]
listen = "0.0.0.0:7443"
authorized_clients = ["`+mustPin(t)+`"]
`+line+`
`)
}

// TestAgentMutationOptIn_AbsentIsOff is the case that matters most, because it
// is the one nobody writes down: a configuration that says nothing about
// remote changes must not permit them. The whole safety of the default rests
// on a zero value, which no line of code asserts on its own.
func TestAgentMutationOptIn_AbsentIsOff(t *testing.T) {
	unsetAllQLEnv(t)
	cfg, err := config.Load(agentWithMutationKey(t, ""))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.AllowRemoteRouteMutation {
		t.Error("a config that never mentions remote route mutation permits it")
	}
}

// TestAgentMutationOptIn_ExplicitOff covers the operator who wrote the answer
// down. It reaches the same conclusion by a different route through the
// decoder, which is why it is not the same test as the one above.
func TestAgentMutationOptIn_ExplicitOff(t *testing.T) {
	unsetAllQLEnv(t)
	cfg, err := config.Load(agentWithMutationKey(t, "allow_remote_route_mutation = false"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.AllowRemoteRouteMutation {
		t.Error("an explicit false was read as true")
	}
}

// TestAgentMutationOptIn_ExplicitOn proves the setting can actually be turned
// on. Without it, the two tests above would pass against a field nothing ever
// sets, and the default would look safe for the wrong reason.
func TestAgentMutationOptIn_ExplicitOn(t *testing.T) {
	unsetAllQLEnv(t)
	cfg, err := config.Load(agentWithMutationKey(t, "allow_remote_route_mutation = true"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Agent.AllowRemoteRouteMutation {
		t.Error("an explicit true was not read")
	}
}

// TestAgentMutationOptIn_MisspelledKeyIsRefused matters more than it looks.
// The key is only useful if the exact spelling that turns it on is the only one
// accepted: a near miss that loaded silently would leave an operator convinced
// they had switched something on.
func TestAgentMutationOptIn_MisspelledKeyIsRefused(t *testing.T) {
	unsetAllQLEnv(t)
	_, err := config.Load(agentWithMutationKey(t, "allow_remote_route_mutations = true"))
	if err == nil {
		t.Fatal("a misspelled opt-in key loaded without complaint")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "allow_remote_route_mutations") {
		t.Errorf("the error does not name the key that was not understood: %v", err)
	}
}

// TestAgentMutationOptIn_WrongTypeIsRefused keeps a value that looks like a
// yes from being read as one. A string where a true or false belongs is a
// mistake worth reporting, not something to interpret.
func TestAgentMutationOptIn_WrongTypeIsRefused(t *testing.T) {
	unsetAllQLEnv(t)
	_, err := config.Load(agentWithMutationKey(t, `allow_remote_route_mutation = "yes"`))
	if err == nil {
		t.Fatal(`allow_remote_route_mutation = "yes" was accepted`)
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestAgentMutationOptIn_ClientRoleSaysNothingAboutIt pins a deliberate
// silence. One configuration file is commonly shared by both roles, so an
// agent-only setting appearing in a client-role run is ordinary rather than
// suspect, and warning about it would teach an operator to ignore warnings.
// The value still survives loading; it simply goes unread.
func TestAgentMutationOptIn_ClientRoleSaysNothingAboutIt(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+pin+`"
[agent]
listen = "0.0.0.0:7443"
authorized_clients = ["`+pin+`"]
allow_remote_route_mutation = true
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "allow_remote_route_mutation") {
			t.Errorf("a client-role run warned about an agent-only setting: %q", w)
		}
	}
	if !cfg.Agent.AllowRemoteRouteMutation {
		t.Error("the value did not survive loading under the client role")
	}
}
