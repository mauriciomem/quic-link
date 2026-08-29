package config_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
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

// TestMergeEnv_UnknownVariableWarnsAndDoesNotFail pins both halves of how an
// unrecognised variable is treated. It used to be discarded in silence, while an
// unknown key in the file was refused outright — so a plausible guess at a
// variable name had no effect and gave no clue, which is the least helpful of the
// four possible pairings.
//
// It must warn and not fail. The prefix is not reserved: somebody may keep their
// own variables in it, or a wrapper may set one a newer version reads, and
// neither is a reason to refuse to start.
func TestMergeEnv_UnknownVariableWarnsAndDoesNotFail(t *testing.T) {
	// An empty path means the default location, so the home directory has to be
	// somewhere this test owns. Without that it reads whatever the person running
	// it happens to have configured, and asserts against their machine.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUIC_LINK_SERVERS_WEB1_ADDR", "127.0.0.1:7443")
	t.Setenv("QUIC_LINK_NOT_A_REAL_KEY", "x")

	// Capture the log, because the whole point of the change is that something is
	// said. Asserting only that the load succeeds would pass just as well with the
	// warning deleted, which is the shape of test this project has been bitten by.
	var logged bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(restore)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("an unrecognised variable must not stop a load: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned no config")
	}
	// And it must not have invented a server from a variable nothing reads.
	if len(cfg.Servers) != 0 {
		t.Errorf("servers = %v, want none: a server cannot be defined by the environment", cfg.Servers)
	}

	out := logged.String()
	if !strings.Contains(out, "QUIC_LINK_SERVERS_WEB1_ADDR") {
		t.Errorf("the warning must name the variable that was ignored; log was:\n%s", out)
	}
	if !strings.Contains(out, "QUIC_LINK_NOT_A_REAL_KEY") {
		t.Errorf("every ignored variable must be named; log was:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("it must be a warning, not a lower level nobody sees; log was:\n%s", out)
	}
}

// TestMergeEnv_RecognisedVariableStillApplies is the other side of the same
// change: adding a warning for the unknown must not have stopped the known from
// working.
func TestMergeEnv_RecognisedVariableStillApplies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// "internal" is the reserved-for-private-use default; an arbitrary suffix is
	// refused unless the operator says they own it, which is a separate rule and
	// not what this test is about.
	t.Setenv("QUIC_LINK_NAMES_SUFFIX", "internal")
	t.Setenv("QUIC_LINK_LOG_LEVEL", "debug")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	n, err := cfg.Naming()
	if err != nil {
		t.Fatalf("Naming: %v", err)
	}
	if n.Suffix != "internal" {
		t.Errorf("suffix = %q, want %q from the environment", n.Suffix, "internal")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log level = %q, want %q from the environment", cfg.Log.Level, "debug")
	}
}

// ---- pin strict refusal ------------------------------------------------------
//
// /**
//  * @spec-handoff
//  * @interface Config.Load(path string) (*Config, error);
//  *            (c *Config) Validate(active Role) (warnings []string, err error)
//  * @behavior
//  *   - Strict-everywhere is the contract: any pin that is not already
//  *     byte-identical to identity.ParsePin's canonical return value is
//  *     REFUSED, not repaired, at every one of the three internal/config/config.go
//  *     entry points (servers.<name>.pin, agent.authorized_clients[*] under
//  *     RoleAgent, and the same field under the RoleClient warning path) and at
//  *     the CLI-flag entry point (cmd/quic-link/util.go's pinList.Set, covering
//  *     --authorized-client).
//  *   - The refusal is a load-time error wrapping config.ErrInvalid, carrying
//  *     the offending config key (e.g. "servers.s1" or
//  *     "agent.authorized_clients[0]") and the literal words "pin" and
//  *     "canonical" — never remedy-naming prose. The message is deliberately
//  *     minimal; it states the rule, not how to fix it.
//  *   - No operator-visible slog.Warn fires for this condition anywhere. The
//  *     prior lenient behavior (normalize in memory, warn) is gone: a
//  *     non-canonical pin is refused outright.
//  *   - This covers BOTH ways a pin can fail to be canonical: surrounding
//  *     whitespace, and a non-canonical base64 trailing-bit spelling of the
//  *     same 32-byte digest.
//  * @edge-cases
//  *   - The RoleClient warning-collection path (validateAgentWarnings) treats
//  *     a non-canonical pin exactly the way it already treats any other
//  *     invalid pin: append a warning string and continue, never a hard
//  *     error — that path's contract (collect problems, do not abort) predates
//  *     this change and is not altered by it.
//  *   - A canonical pin (server or authorized_clients) is completely
//  *     unaffected: Load+Validate succeed and the stored value is unchanged,
//  *     which is what every pre-existing fixture in this file already
//  *     exercises.
//  * @see internal/identity/pin.go (ParsePin, ParsePinStrict),
//  *      internal/identity/tls.go (pinningTLS, verifyPin — unchanged by this
//  *      spec; verifyPin's exact-comparison contract stays exactly as it was).
//  */

// nonCanonicalPinSpelling returns a validly-decoding base64 spelling of the
// SAME 32-byte digest as canonical, but byte-different from it — Go's
// base64.StdEncoding.DecodeString accepts more than one spelling for the
// final 6-bit group of a padded value, because the two padding bits it
// discards are not required to be zero. Flipping the low bit of the
// second-to-last character (while holding the encoded value's length and
// validity) produces exactly such an alternate spelling.
//
// t.Fatal fires if canonical is not the padded, unpadded-input-length shape
// this construction assumes (44 characters, one trailing '='), which is what
// base64.StdEncoding.EncodeToString of a 32-byte SHA-256 always produces —
// so this only fails if a caller passes something else by mistake.
func nonCanonicalPinSpelling(t *testing.T, canonical string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(canonical) < 2 || canonical[len(canonical)-1] != '=' {
		t.Fatalf("nonCanonicalPinSpelling: %q is not a padded base64(32 bytes) pin", canonical)
	}
	idx := len(canonical) - 2
	pos := strings.IndexByte(alphabet, canonical[idx])
	if pos < 0 {
		t.Fatalf("nonCanonicalPinSpelling: %q not in base64 alphabet", string(canonical[idx]))
	}
	flipped := (pos &^ 0x3) | ((pos & 0x3) ^ 0x1)
	variant := canonical[:idx] + string(alphabet[flipped]) + canonical[idx+1:]
	if variant == canonical {
		t.Fatal("nonCanonicalPinSpelling: flip produced no change; test construction is broken")
	}
	rawCanon, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatalf("nonCanonicalPinSpelling: canonical does not decode: %v", err)
	}
	rawVariant, err := base64.StdEncoding.DecodeString(variant)
	if err != nil {
		t.Fatalf("nonCanonicalPinSpelling: variant does not decode: %v", err)
	}
	if string(rawCanon) != string(rawVariant) {
		t.Fatalf("nonCanonicalPinSpelling: variant decodes to a different digest than canonical")
	}
	return variant
}

// TestForwardModePin_PaddedPinIsRefused is the headline regression, inverted:
// a server pin in a config file with trailing whitespace (the exact shape the
// operator A/B-reproduced — pasted with two trailing spaces) must now be
// REFUSED by Validate, not silently canonicalized. A pin is an authentication
// credential; the correct response to a non-canonical spelling is refusal at
// load, not a normalize-and-continue that leaves the mismatch invisible until
// a peer is rejected at the TLS layer.
func TestForwardModePin_PaddedPinIsRefused(t *testing.T) {
	unsetAllQLEnv(t)
	canonical := mustPin(t)
	padded := canonical + "  " // the operator's reproduction: two trailing spaces
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+padded+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected a refusal for a padded server pin, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "servers.s1") {
		t.Errorf("error %q does not name the offending server", err.Error())
	}
	if !strings.Contains(err.Error(), "pin") || !strings.Contains(err.Error(), "canonical") {
		t.Errorf("error %q does not state the pin-is-not-canonical rule", err.Error())
	}
}

// TestAuthorizedClientPin_PaddedPinIsRefused is the same regression at the
// second entry point: an agent's authorized_clients entry with trailing
// whitespace must be refused under Validate(RoleAgent), the hard-error path
// for the agent role.
func TestAuthorizedClientPin_PaddedPinIsRefused(t *testing.T) {
	unsetAllQLEnv(t)
	canonical := mustPin(t)
	padded := canonical + "  "
	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+padded+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatal("expected a refusal for a padded authorized_clients pin, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "agent.authorized_clients[0]") {
		t.Errorf("error %q does not name the offending key", err.Error())
	}
	if !strings.Contains(err.Error(), "pin") || !strings.Contains(err.Error(), "canonical") {
		t.Errorf("error %q does not state the pin-is-not-canonical rule", err.Error())
	}
}

// TestAuthorizedClientPin_PaddedPinIsWarnedOnClientRolePath covers the THIRD
// entry point: the same authorized_clients field, but reached through
// validateAgentWarnings — the path taken when the active role is RoleClient
// and an [agent] block is merely present-but-inactive. This path collects
// warning strings for every kind of invalid pin rather than hard-failing (an
// unparseable pin here has always produced a warning, never aborted load);
// a non-canonical-but-decodable pin is now treated identically, since both
// are refusals of the same underlying rule, and inventing a fourth behavior
// (hard error) here would break this path's existing "collect, don't abort"
// contract.
func TestAuthorizedClientPin_PaddedPinIsWarnedOnClientRolePath(t *testing.T) {
	unsetAllQLEnv(t)
	canonical := mustPin(t)
	padded := canonical + "  "
	serverPin := mustPin(t)
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+serverPin+`"
[agent]
listen = ":7443"
dial   = "host:7443"
authorized_clients = ["`+padded+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// RoleClient is active; the [agent] block is present-but-inactive, so its
	// problems (including a non-canonical pin) surface as warnings, not a
	// hard error, matching how this path already treats an unparseable pin.
	warnings, err := cfg.Validate(config.RoleClient)
	if err != nil {
		t.Fatalf("Validate(RoleClient): unexpected hard error: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "authorized_clients[0]") &&
			strings.Contains(w, "pin") && strings.Contains(w, "canonical") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about authorized_clients[0]'s non-canonical pin, got: %v", warnings)
	}
	// The raw padded string must NOT have been silently canonicalized in
	// place — refusal means the stored value is left exactly as the file
	// supplied it, since it was never accepted.
	got := cfg.Agent.AuthorizedClients[0]
	if got != padded {
		t.Errorf("agent.authorized_clients[0] = %q, want the untouched raw value %q "+
			"(a refused pin must not be silently rewritten)", got, padded)
	}
}

// TestAgentAuthorizedClient_PaddedPin_RefusedAtConfigLoad inverts the meaning
// of the old end-to-end test, not just its assertion direction: a padded pin
// must now fail at CONFIG LOAD, so the handshake path is never reached at
// all. The old test proved a padded pin eventually authenticated once
// canonicalized; the new rule is that it never gets that far.
func TestAgentAuthorizedClient_PaddedPin_RefusedAtConfigLoad(t *testing.T) {
	unsetAllQLEnv(t)
	clientKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate (client key): %v", err)
	}
	canonicalClientPin, err := identity.PinForKey(clientKey)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	padded := canonicalClientPin + "  " // the operator's exact reproduction

	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+padded+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleAgent)
	if err == nil {
		t.Fatal("expected Validate(RoleAgent) to refuse a padded authorized_clients pin, got nil — " +
			"the handshake must never be reached with a non-canonical stored pin")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestAgentAuthorizedClient_CanonicalPin_HandshakeSucceedsEndToEnd retains
// end-to-end coverage of the happy path now that the padded-pin end-to-end
// test above no longer reaches the handshake: it drives Load+Validate exactly
// as agent.go does, then feeds the resulting AuthorizedClients slice directly
// into identity.AgentListenTLS (the same call agent.go makes, with no further
// ParsePin step in between) and asserts the resulting tls.Config's
// VerifyPeerCertificate callback ACCEPTS a legitimate peer presenting the
// canonical spelling of the same key that was configured, canonically, from
// the start.
//
// This is deliberately not a live UDP/QUIC handshake — VerifyPeerCertificate
// is the exact function net/tls invokes mid-handshake, and calling it
// directly with a real certificate exercises the identical code path without
// the cost or flakiness of a full QUIC session.
func TestAgentAuthorizedClient_CanonicalPin_HandshakeSucceedsEndToEnd(t *testing.T) {
	unsetAllQLEnv(t)
	agentKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate (agent key): %v", err)
	}
	clientKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate (client key): %v", err)
	}
	canonicalClientPin, err := identity.PinForKey(clientKey)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}

	path := writeConfig(t, `
schema = 1
[agent]
listen = ":7443"
authorized_clients = ["`+canonicalClientPin+`"]
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.Validate(config.RoleAgent); err != nil {
		t.Fatalf("Validate(RoleAgent): %v", err)
	}

	// agent.go passes cfg.Agent.AuthorizedClients straight into
	// identity.AgentListenTLS/AgentDialTLS with no further parsing — see
	// cmd/quic-link/agent.go's effectiveClients / agentRun.
	serverTLS, err := identity.AgentListenTLS(agentKey, cfg.Agent.AuthorizedClients)
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	clientCert, err := identity.SelfSignedCarrier(clientKey)
	if err != nil {
		t.Fatalf("SelfSignedCarrier: %v", err)
	}

	if err := serverTLS.VerifyPeerCertificate(clientCert.Certificate, nil); err != nil {
		t.Fatalf("legitimate client REJECTED: %v — a canonically-configured "+
			"authorized_clients entry must still authenticate its own peer", err)
	}
}

// TestNonCanonicalPinSpelling_IsRefused documents and locks in the inverted
// consequence of strict refusal: Go's base64.StdEncoding.DecodeString is
// non-strict about certain trailing-bit spellings of a padded value, so more
// than one input string can decode to the identical 32-byte digest. This is
// the case the user considers most suspicious — no human types this spelling
// by accident, so it implies a corrupted pin or a buggy generator, and
// leniency here bought nothing. After this change, config.Load+Validate must
// REFUSE such a spelling rather than canonicalize it.
func TestNonCanonicalPinSpelling_IsRefused(t *testing.T) {
	unsetAllQLEnv(t)
	canonical := mustPin(t)
	variant := nonCanonicalPinSpelling(t, canonical)

	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+variant+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected a refusal for a non-canonical base64 spelling, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
}

// TestValidate_RefusesRatherThanWarnsWhenStoredPinIsNotCanonical replaces the
// old warning-only assertion: a non-canonical pin must be a startup config
// error (exit 2), never a warning. This test asserts the refusal fires and
// that no WARN-level record about it is emitted — a warning here would mean
// the deliberately-removed leniency crept back in.
func TestValidate_RefusesRatherThanWarnsWhenStoredPinIsNotCanonical(t *testing.T) {
	unsetAllQLEnv(t)
	canonical := mustPin(t)
	padded := canonical + "  "
	path := writeConfig(t, `
schema = 1
[servers.s1]
addr = "1.2.3.4:7443"
pin  = "`+padded+`"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var logged bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(restore)

	_, err = cfg.Validate(config.RoleClient)
	if err == nil {
		t.Fatal("expected a refusal for a non-canonical stored pin, got nil")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("a non-canonical pin must be REFUSED, not warned about; "+
			"unexpected WARN-level log:\n%s", logged.String())
	}
}
