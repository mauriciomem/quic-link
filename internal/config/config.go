// Package config loads, merges, and validates quic-link configuration.
// The source order is: built-in defaults < config file < environment variables.
// Flag overrides are applied by the caller after Load returns.
//
// The config file format is TOML; the schema is defined in
// docs/configuration.md. Structural errors (unknown keys, wrong
// types) are detected by strict decoding. Semantic errors (missing required
// fields, invalid pins) are detected by Validate.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
// keys defined in the schema.
type Config struct {
	Schema   int               `toml:"schema"`
	Identity Identity          `toml:"identity"`
	Servers  map[string]Server `toml:"servers"`
	Agent    *Agent            `toml:"agent"`
	Names    *Names            `toml:"names"`
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
// Vhosts publishes services under hostnames, which is how a client that routes
// by name — a browser, say — reaches them.
type Agent struct {
	Listen            string            `toml:"listen"`
	Dial              string            `toml:"dial"`
	AuthorizedClients []string          `toml:"authorized_clients"`
	Routes            map[string]string `toml:"routes"`
	Vhosts            map[string]string `toml:"vhosts"` // hostname -> address
	// AllowRemoteRouteMutation lets an authenticated client publish a name on
	// this agent while it is running. Off unless the operator says otherwise:
	// a client is trusted to reach the services this agent already publishes,
	// which is a smaller thing than being trusted to decide what it publishes.
	//
	// It is deliberately settable only here, in a file, and not by a flag or
	// an environment variable. A setting that can be turned on from the
	// process environment can be turned on by anything that prepares that
	// environment — a service unit, a container definition, a wrapper script —
	// which is a much wider and less reviewable surface than a file somebody
	// edited on purpose.
	//
	// Only the agent role reads it. A configuration shared between roles may
	// carry it harmlessly.
	AllowRemoteRouteMutation bool `toml:"allow_remote_route_mutation"`
}

// Log controls structured logging behavior.
type Log struct {
	Level  string `toml:"level"`  // default info
	Format string `toml:"format"` // default text
}

// Names is the [names] table as written in the config file. It is the raw
// shape; Config.Naming turns it into a checked one. Nothing outside that
// method should read these fields.
type Names struct {
	Suffix    string `toml:"suffix"`
	DNSPort   int    `toml:"dns_port"`
	HTTPPort  int    `toml:"http_port"`
	HTTPSPort int    `toml:"https_port"`

	// SuffixIsMine is the operator asserting that they control a suffix which
	// is not reserved for private use. It exists so that pointing the system
	// resolver at a real domain is a deliberate act rather than a typo.
	SuffixIsMine bool `toml:"suffix_is_mine"`
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

	// Look for keys that used to exist before decoding strictly. Strict
	// decoding would report them as merely unknown, which is true but unhelpful
	// for a key that shipped as documented and reserved: the reader needs to
	// know it was taken away on purpose and what replaced it. A file too
	// malformed to survey is left to the strict decoder to complain about.
	var survey map[string]any
	if toml.Unmarshal(data, &survey) == nil {
		if err := checkRemovedKeys(path, survey); err != nil {
			return err
		}
	}

	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		var sme *toml.StrictMissingError
		if errors.As(err, &sme) {
			return fmt.Errorf(
				"config %s: unknown key or table:\n%s\nsee docs/configuration.md for valid keys: %w",
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
// scalar can be set. The same applies to Names.
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
		return removedKeyError("QUIC_LINK_PORTS_MODE", removedPortsTable)

	case "QUIC_LINK_NAMES_SUFFIX":
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.Suffix = val

	case "QUIC_LINK_NAMES_BLOCK":
		return removedKeyError("QUIC_LINK_NAMES_BLOCK", removedNamesBlock)

	case "QUIC_LINK_NAMES_DNS_PORT":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be an integer: %w", key, val, ErrInvalid)
		}
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.DNSPort = n

	case "QUIC_LINK_NAMES_HTTP_PORT":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be an integer: %w", key, val, ErrInvalid)
		}
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.HTTPPort = n

	case "QUIC_LINK_NAMES_HTTPS_PORT":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be an integer: %w", key, val, ErrInvalid)
		}
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.HTTPSPort = n

	case "QUIC_LINK_NAMES_SUFFIX_IS_MINE":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("env %s=%q: must be a boolean (true/false/1/0): %w", key, val, ErrInvalid)
		}
		if cfg.Names == nil {
			cfg.Names = &Names{}
		}
		cfg.Names.SuffixIsMine = b
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
		// The naming table is checked first because it is machine-wide: a bad
		// suffix would be written into the system resolver and affect every
		// lookup, which matters more than any single server's settings.
		if _, e := c.Naming(); e != nil {
			return warnings, e
		}
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
		// The naming layer is client-side, so a bad [names] table cannot hurt
		// an agent — but it is still wrong, and a shared config file is common.
		if _, e := c.Naming(); e != nil {
			warnings = append(warnings, fmt.Sprintf("names (inactive for agent role): %v", e))
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
	if err := validateDistinctListenPins(c.Servers); err != nil {
		return warns, err
	}
	return warns, nil
}

// validateDistinctListenPins rejects two servers that wait to be connected to
// while sharing a pin, which means sharing a keypair.
//
// A server this machine dials is identified by its address, so two of those may
// share an identity harmlessly. A server that waits has no address of its own to
// tell it apart by: an inbound peer presenting that pin could belong to either
// entry, and a log line naming the peer would name both. The check is therefore
// scoped to waiting servers only, and skips disabled ones, which are never
// managed and so can never receive a connection.
//
// Servers are visited in sorted order so the same pair is always reported for a
// given config rather than whichever the map happened to yield first.
func validateDistinctListenPins(servers map[string]Server) error {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	firstSeenAt := make(map[string]string, len(names))
	for _, name := range names {
		srv := servers[name]
		if srv.Enabled != nil && !*srv.Enabled {
			continue
		}
		if srv.Listen == "" || srv.Addr != "" {
			continue
		}
		if other, dup := firstSeenAt[srv.Pin]; dup {
			return fmt.Errorf(
				"servers.%s and servers.%s share a pin; servers that wait to be "+
					"connected to must each have their own key, because an incoming "+
					"connection is identified by its pin and nothing else could tell "+
					"the two apart: %w",
				other, name, ErrInvalid,
			)
		}
		firstSeenAt[srv.Pin] = name
	}
	return nil
}

// validateServer validates one server entry and returns a wrapped ErrInvalid on
// the first problem found.
func validateServer(name string, srv Server) error {
	// The name becomes the first label of a hostname, so it has to be able to
	// be one. This is checked before anything else because it is the only
	// problem here that a user cannot see by reading their own file.
	if err := ValidateServerName(name); err != nil {
		return fmt.Errorf("servers.%s: %v: %w", name, err, ErrInvalid)
	}

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

	// Validate each route name and address using the same validator/parser
	// the router and the --route flag use, so a bad name or address is
	// rejected identically no matter where it was set.
	for target, addr := range a.Routes {
		if err := router.ValidateRouteName(target); err != nil {
			return fmt.Errorf("agent.routes: %v: %w", err, ErrInvalid)
		}
		if _, _, err := router.ParseAddr(addr); err != nil {
			return fmt.Errorf("agent.routes.%s: %v: %w", target, err, ErrInvalid)
		}
	}

	// Published hostnames follow a different rule from route names, because
	// they are hostnames: a browser will be told to ask for one.
	for host, addr := range a.Vhosts {
		if err := router.ValidateVhostKey(host); err != nil {
			return fmt.Errorf("agent.vhosts: %v: %w", err, ErrInvalid)
		}
		if _, _, err := router.ParseAddr(addr); err != nil {
			return fmt.Errorf("agent.vhosts.%s: %v: %w", host, err, ErrInvalid)
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
		if err := router.ValidateRouteName(target); err != nil {
			w = append(w, fmt.Sprintf("agent (inactive for client role): routes: %v", err))
		}
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

// ---- Removed keys -----------------------------------------------------------

// Explanations for configuration that existed in an earlier release. A key
// listed here is refused with its reason rather than reported as unknown,
// because "unknown key" reads like a typo and these are not typos: they were
// documented, and somebody may have written them down.
const (
	removedPortsTable = "quic-link does not bind ports the operating system reserves, so there are " +
		"no port modes to choose between. The naming layer's ports are set individually " +
		"under [names] as dns_port, http_port and https_port, and each must be above 1023."

	removedNamesBlock = "the naming layer listens on 127.0.0.1 and tells servers apart by port and " +
		"by the hostname the client sends, so there is no address range to set aside."
)

// removedKeyError formats the refusal for one removed key.
func removedKeyError(what, why string) error {
	return fmt.Errorf("%s is no longer used: %s Remove it: %w", what, why, ErrInvalid)
}

// checkRemovedKeys reports the first removed key present in a surveyed file.
func checkRemovedKeys(path string, survey map[string]any) error {
	if _, ok := survey["ports"]; ok {
		return fmt.Errorf("config %s: %w", path, removedKeyError("the [ports] table", removedPortsTable))
	}
	if servers, ok := survey["servers"].(map[string]any); ok {
		if _, ok := servers[FlagOnlyServerName]; ok {
			return fmt.Errorf(
				"config %s: %q is reserved for a server built from command-line flags and "+
					"cannot be used in a file; choose a name that can be part of a hostname: %w",
				path, FlagOnlyServerName, ErrInvalid)
		}
	}
	if names, ok := survey["names"].(map[string]any); ok {
		if _, ok := names["block"]; ok {
			return fmt.Errorf("config %s: %w", path, removedKeyError("names.block", removedNamesBlock))
		}
	}
	return nil
}
