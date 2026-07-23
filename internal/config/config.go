// Package config loads, merges, and validates quic-link configuration.
// The source order is: built-in defaults < config file < environment variables.
// Flag overrides are applied by the caller after Load returns.
//
// The config file format is TOML; the schema is defined in
// internal-docs/docs/05-config.md. Structural errors (unknown keys, wrong
// types) are detected by strict decoding. Semantic errors (missing required
// fields, invalid pins) are detected by Validate.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
)

// ErrInvalid is the sentinel for all configuration errors (structural or
// semantic). The caller maps errors.Is(err, config.ErrInvalid) to exit code 2.
var ErrInvalid = errors.New("invalid configuration")

// ---- Types ------------------------------------------------------------------

// Config is the top-level configuration structure. Field names match the TOML
// keys defined in the schema. Reserved tables (Names, Ports) are parsed but
// have no behavior in the current release; they are present so strict decoding
// does not reject a valid future-facing config that includes them.
type Config struct {
	Schema   int               `toml:"schema"`
	Identity Identity          `toml:"identity"`
	Servers  map[string]Server `toml:"servers"`
	Agent    *Agent            `toml:"agent"`
	Names    *Names            `toml:"names"`
	Ports    *Ports            `toml:"ports"`
	Log      Log               `toml:"log"`
}

// Identity holds key-file path and key-age hygiene settings.
type Identity struct {
	KeyFile        string `toml:"key_file"`
	WarnKeyAgeDays int    `toml:"warn_key_age_days"` // 0 disables; default 180
	RefuseOldKey   bool   `toml:"refuse_old_key"`    // default false
}

// Server describes one named remote endpoint. Addr and Listen are mutually
// exclusive: Addr means this machine dials, Listen means this machine waits
// for the agent to dial in (reverse mode). Pin is always required.
type Server struct {
	Addr       string         `toml:"addr"`
	Listen     string         `toml:"listen"`
	Pin        string         `toml:"pin"`
	Enabled    *bool          `toml:"enabled"` // nil ≡ true (pointer detects unset)
	LocalPorts map[string]int `toml:"local_ports"`
}

// Agent holds agent-role settings. Listen and Dial are mutually exclusive.
// Vhosts is reserved for a future release; it parses so a config that includes
// it is not rejected by strict decoding.
type Agent struct {
	Listen            string            `toml:"listen"`
	Dial              string            `toml:"dial"`
	AuthorizedClients []string          `toml:"authorized_clients"`
	Routes            map[string]string `toml:"routes"`
	Vhosts            map[string]string `toml:"vhosts"` // reserved; no behavior yet
}

// Log controls structured logging behavior.
type Log struct {
	Level  string `toml:"level"`  // default info
	Format string `toml:"format"` // default text
}

// Names is reserved for the naming/DNS layer. Its fields cover the keys
// specified in the schema so strict decoding accepts a config that sets them.
type Names struct {
	Suffix  string `toml:"suffix"`
	Block   string `toml:"block"`
	DNSPort int    `toml:"dns_port"`
}

// Ports is reserved for the port-mode setting. Parsed but inert.
type Ports struct {
	Mode string `toml:"mode"`
}

// ---- Role -------------------------------------------------------------------

// Role identifies which side of the tunnel a running process is playing, used
// by Validate to decide which section's problems are hard errors vs. warnings.
type Role int

const (
	RoleClient Role = iota
	RoleAgent
)

// ---- Defaults ---------------------------------------------------------------

// Defaults returns a Config populated with built-in defaults. It is the
// baseline before file and environment overrides are applied.
func Defaults() *Config {
	kf := defaultKeyFilePath()
	return &Config{
		Identity: Identity{
			KeyFile:        kf,
			WarnKeyAgeDays: 180,
			RefuseOldKey:   false,
		},
		Log: Log{
			Level:  "info",
			Format: "text",
		},
	}
}

// defaultKeyFilePath resolves ~/.config/quic-link/key.pem using
// os.UserHomeDir so the same path is used on every OS. os.UserConfigDir is
// NOT used because on macOS it returns ~/Library/Application Support.
func defaultKeyFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "key.pem"
	}
	return filepath.Join(home, ".config", "quic-link", "key.pem")
}

// defaultConfigFilePath resolves ~/.config/quic-link/config.toml.
func defaultConfigFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "config.toml"
	}
	return filepath.Join(home, ".config", "quic-link", "config.toml")
}

// ---- Load -------------------------------------------------------------------

// Load builds a Config by applying defaults, then the config file (if any),
// then environment variables. path is the file path; an empty string means the
// default location (~/.config/quic-link/config.toml). A missing default file
// is not an error. An explicitly provided path that does not exist is an error.
//
// Load performs structural validation only (schema version, unknown keys, type
// mismatches, tilde expansion). Semantic role checks belong in Validate.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	explicitPath := path != ""
	if !explicitPath {
		path = defaultConfigFilePath()
	}

	if err := loadFile(cfg, path, explicitPath); err != nil {
		return nil, err
	}

	if err := mergeEnv(cfg); err != nil {
		return nil, err
	}

	// Structural check: schema 0 (absent) is treated as 1. Any other value
	// besides 1 is unsupported.
	if cfg.Schema == 0 {
		cfg.Schema = 1
	} else if cfg.Schema != 1 {
		return nil, fmt.Errorf("unsupported schema %d (only schema 1 is supported): %w", cfg.Schema, ErrInvalid)
	}

	// Expand a leading ~ in the key file path so the value is always absolute
	// after Load returns, regardless of whether it came from a default, file,
	// or environment override.
	cfg.Identity.KeyFile = expandTilde(cfg.Identity.KeyFile)

	return cfg, nil
}

// loadFile decodes path into cfg. If the file does not exist and
// explicitPath is false the function is a no-op (missing default is fine).
func loadFile(cfg *Config, path string, explicitPath bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if explicitPath {
				return fmt.Errorf("config file %s not found: %w", path, ErrInvalid)
			}
			return nil // missing default is fine
		}
		return fmt.Errorf("read config %s: %w", path, ErrInvalid)
	}

	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		var sme *toml.StrictMissingError
		if errors.As(err, &sme) {
			return fmt.Errorf(
				"config %s: unknown key or table:\n%s\nsee internal-docs/docs/05-config.md for valid keys: %w",
				path, sme.String(), ErrInvalid,
			)
		}
		var de *toml.DecodeError
		if errors.As(err, &de) {
			return fmt.Errorf("config %s: type error:\n%s: %w", path, de.String(), ErrInvalid)
		}
		return fmt.Errorf("config %s: %w: %w", path, err, ErrInvalid)
	}
	return nil
}

// ---- Environment overlay ----------------------------------------------------

// mergeEnv reads QUIC_LINK_* environment variables and overlays their values
// onto cfg. Only scalar (non-table) keys are supported via environment; table-
// typed values (servers.*, authorized_clients, routes, local_ports, vhosts)
// must come from the config file or flags.
//
// If QUIC_LINK_AGENT_* is set and cfg.Agent is nil, Agent is allocated so the
// scalar can be set. The same applies to Ports and Names.
func mergeEnv(cfg *Config) error {
	for _, env := range os.Environ() {
		key, val, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(key, "QUIC_LINK_") {
			continue
		}
		if err := applyEnvVar(cfg, key, val); err != nil {
			return err
		}
	}
	return nil
}

// applyEnvVar maps a single QUIC_LINK_* variable onto the matching config field.
func applyEnvVar(cfg *Config, key, val string) error {
	switch key {
	case "QUIC_LINK_SCHEMA":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be an integer: %w", key, val, ErrInvalid)
		}
		cfg.Schema = n

	case "QUIC_LINK_IDENTITY_KEY_FILE":
		cfg.Identity.KeyFile = val

	case "QUIC_LINK_IDENTITY_WARN_KEY_AGE_DAYS":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be an integer: %w", key, val, ErrInvalid)
		}
		cfg.Identity.WarnKeyAgeDays = n

	case "QUIC_LINK_IDENTITY_REFUSE_OLD_KEY":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be a boolean (true/false/1/0): %w", key, val, ErrInvalid)
		}
		cfg.Identity.RefuseOldKey = b

	case "QUIC_LINK_AGENT_LISTEN":
		if cfg.Agent == nil {
			cfg.Agent = &Agent{}
		}
		cfg.Agent.Listen = val

	case "QUIC_LINK_AGENT_DIAL":
		if cfg.Agent == nil {
			cfg.Agent = &Agent{}
		}
		cfg.Agent.Dial = val

	case "QUIC_LINK_LOG_LEVEL":
		cfg.Log.Level = val

	case "QUIC_LINK_LOG_FORMAT":
		cfg.Log.Format = val

	case "QUIC_LINK_PORTS_MODE":
		if cfg.Ports == nil {
			cfg.Ports = &Ports{}
		}
		cfg.Ports.Mode = val

	case "QUIC_LINK_NAMES_SUFFIX":
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.Suffix = val

	case "QUIC_LINK_NAMES_BLOCK":
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.Block = val

	case "QUIC_LINK_NAMES_DNS_PORT":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be an integer: %w", key, val, ErrInvalid)
		}
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.DNSPort = n
	}
	return nil
}

// ---- Validate ---------------------------------------------------------------

// Validate checks semantic rules against cfg for the given active role.
// Problems in the active role are hard errors (wrapped ErrInvalid). Problems
// in a present-but-inactive role are returned as advisory warning strings.
// Structural errors were already caught in Load.
//
// The caller should log each warning string (e.g. slog.Warn) before deciding
// whether to proceed. A non-nil returned error should abort startup (exit 2).
func (c *Config) Validate(active Role) (warnings []string, err error) {
	switch active {
	case RoleClient:
		// Enabled server problems are hard errors; disabled server problems
		// are warnings (a disabled server is not selectable and not on the
		// active path).
		srvWarns, e := validateServers(c)
		warnings = append(warnings, srvWarns...)
		if e != nil {
			return warnings, e
		}
		// Agent section problems (if the agent block is present) are warnings.
		if c.Agent != nil {
			warnings = append(warnings, validateAgentWarnings(c.Agent)...)
		}
	case RoleAgent:
		// Agent section problems are hard errors for the agent role.
		if e := validateAgent(c); e != nil {
			return warnings, e
		}
		// Server section problems (if any servers are present) are warnings.
		warnings = append(warnings, validateServersWarnings(c.Servers)...)
	}
	return warnings, nil
}

// validateServers checks all enabled [servers.<name>] blocks and returns the
// first hard error found. A server with enabled=false is skipped for hard
// validation; its problems (if any) are collected as warning strings instead,
// because a disabled server cannot be selected and is not on the active path.
func validateServers(c *Config) ([]string, error) {
	var warns []string
	for name, srv := range c.Servers {
		disabled := srv.Enabled != nil && !*srv.Enabled
		if disabled {
			if err := validateServer(name, srv); err != nil {
				warns = append(warns, fmt.Sprintf("servers.%s (disabled): %v", name, err))
			}
			continue
		}
		if err := validateServer(name, srv); err != nil {
			return warns, err
		}
	}
	return warns, nil
}

// validateServer validates one server entry and returns a wrapped ErrInvalid on
// the first problem found.
func validateServer(name string, srv Server) error {
	bothSet := srv.Addr != "" && srv.Listen != ""
	neitherSet := srv.Addr == "" && srv.Listen == ""
	if bothSet {
		return fmt.Errorf(
			"servers.%s: addr and listen are mutually exclusive; set only one: %w",
			name, ErrInvalid,
		)
	}
	if neitherSet {
		return fmt.Errorf(
			"servers.%s: either addr (forward mode) or listen (reverse mode) is required: %w",
			name, ErrInvalid,
		)
	}
	if _, err := identity.ParsePin(srv.Pin); err != nil {
		return fmt.Errorf("servers.%s: pin is required and must be valid base64(SHA-256): %v: %w",
			name, err, ErrInvalid,
		)
	}
	return nil
}

// validateServersWarnings collects warning strings for server entries that have
// problems (used when servers are present but the active role is agent).
func validateServersWarnings(servers map[string]Server) []string {
	var w []string
	for name, srv := range servers {
		if err := validateServer(name, srv); err != nil {
			w = append(w, fmt.Sprintf("servers.%s (inactive for agent role): %v", name, err))
		}
	}
	return w
}

// validateAgent checks [agent] and returns the first hard error. An absent
// agent block is not checked (that is the role precondition, enforced by the
// verb before calling Validate).
func validateAgent(c *Config) error {
	if c.Agent == nil {
		return fmt.Errorf("agent: [agent] block is required for the agent role: %w", ErrInvalid)
	}
	a := c.Agent

	bothSet := a.Listen != "" && a.Dial != ""
	neitherSet := a.Listen == "" && a.Dial == ""
	if bothSet {
		return fmt.Errorf(
			"agent: listen and dial are mutually exclusive; set only one: %w", ErrInvalid,
		)
	}
	if neitherSet {
		return fmt.Errorf(
			"agent: either listen (forward mode) or dial (reverse mode) is required: %w", ErrInvalid,
		)
	}

	// Empty authorized_clients is a hard error for the agent role regardless
	// of whether servers are present or the active role — authentication is
	// mandatory, and an agent without any authorized client can accept no
	// connections and must not start.
	if len(a.AuthorizedClients) == 0 {
		return fmt.Errorf(
			"agent: authorized_clients must be non-empty; the agent must have at least one"+
				" authorized client pin: %w", ErrInvalid,
		)
	}
	for i, pin := range a.AuthorizedClients {
		if _, err := identity.ParsePin(pin); err != nil {
			return fmt.Errorf("agent.authorized_clients[%d]: invalid pin: %v: %w", i, err, ErrInvalid)
		}
	}

	// Validate each route address using the same parser the router uses, so
	// config validation and runtime behavior are guaranteed consistent.
	for target, addr := range a.Routes {
		if _, _, err := router.ParseAddr(addr); err != nil {
			return fmt.Errorf("agent.routes.%s: %v: %w", target, err, ErrInvalid)
		}
	}

	return nil
}

// validateAgentWarnings collects warning strings for an agent block's problems
// (used when the agent block is present but the active role is client).
func validateAgentWarnings(a *Agent) []string {
	var w []string

	bothSet := a.Listen != "" && a.Dial != ""
	neitherSet := a.Listen == "" && a.Dial == ""
	if bothSet {
		w = append(w, "agent (inactive for client role): listen and dial are mutually exclusive")
	}
	if neitherSet {
		w = append(w, "agent (inactive for client role): either listen or dial is required")
	}

	if len(a.AuthorizedClients) == 0 {
		w = append(w, "agent (inactive for client role): authorized_clients must be non-empty")
	}
	for i, pin := range a.AuthorizedClients {
		if _, err := identity.ParsePin(pin); err != nil {
			w = append(w, fmt.Sprintf("agent (inactive for client role): authorized_clients[%d]: invalid pin: %v", i, err))
		}
	}

	for target, addr := range a.Routes {
		if _, _, err := router.ParseAddr(addr); err != nil {
			w = append(w, fmt.Sprintf("agent (inactive for client role): routes.%s: %v", target, err))
		}
	}

	return w
}

// ---- Helpers ----------------------------------------------------------------

// expandTilde expands a leading ~ or ~/ to the user home directory. Paths
// that do not start with ~ are returned unchanged.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
