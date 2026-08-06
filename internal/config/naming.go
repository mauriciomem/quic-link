package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Default listening ports for the naming layer. All three are deliberately
// above 1023 and outside the ranges anything common registers.
//
// 5355 is NOT used for DNS even though it looks like an obvious choice: it is
// the registered port for Link-Local Multicast Name Resolution, and a stock
// systemd-resolved is already listening on it, so binding it as an ordinary
// user fails outright. 5354 is registered too. 15353 is free.
const (
	DefaultDNSPort   = 15353
	DefaultHTTPPort  = 18080
	DefaultHTTPSPort = 18443

	// DefaultSuffix is in the IANA special-use registry for private use, so it
	// can never become a real top-level domain and can never collide with one.
	DefaultSuffix = "internal"
)

// lowestUnprivilegedPort is the first port an ordinary process may bind on
// both supported systems. quic-link never binds below it, on any platform, by
// any mechanism: a value under it is refused when configuration is read rather
// than discovered as a permission error at startup.
const lowestUnprivilegedPort = 1024

// dnsLabel is one component of a hostname: letters, digits and dashes, not
// starting or ending with a dash, at most 63 characters.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedSuffixes are names set aside by standards bodies for private use, so
// pointing the system resolver at them cannot take a real namespace away from
// anybody. A suffix that is one of these, or sits underneath one, is accepted
// without further ado. Anything else is a namespace someone owns, and the
// operator has to say they are that someone.
var reservedSuffixes = []string{
	"internal",  // reserved by ICANN for private use
	"home.arpa", // reserved for home networks
	"test",      // reserved for testing
}

// Naming is the validated naming configuration: a suffix that is a usable DNS
// name and three ports that an ordinary process can actually bind.
//
// It exists so that no part of the program has to wonder whether the values it
// was handed were checked. Naming values come from Config.Naming and nowhere
// else; consumers take a Naming rather than the raw table, so an unchecked
// value cannot reach them.
type Naming struct {
	// Suffix is lowercase, has no trailing dot, and every label is a valid
	// hostname component.
	Suffix string
	// DNSPort, HTTPPort and HTTPSPort are each above 1023 and distinct from
	// one another.
	DNSPort   int
	HTTPPort  int
	HTTPSPort int
}

// Naming validates the [names] table and returns the resolved configuration.
// An absent table is not an error: every field has a default, so the naming
// layer works with no configuration at all.
func (c *Config) Naming() (Naming, error) {
	raw := c.Names
	if raw == nil {
		raw = &Names{}
	}

	suffix, err := resolveSuffix(raw.Suffix, raw.SuffixIsMine)
	if err != nil {
		return Naming{}, err
	}

	n := Naming{Suffix: suffix}
	for _, p := range []struct {
		key   string
		value int
		def   int
		dst   *int
	}{
		{"dns_port", raw.DNSPort, DefaultDNSPort, &n.DNSPort},
		{"http_port", raw.HTTPPort, DefaultHTTPPort, &n.HTTPPort},
		{"https_port", raw.HTTPSPort, DefaultHTTPSPort, &n.HTTPSPort},
	} {
		v, err := resolveNamingPort(p.key, p.value, p.def)
		if err != nil {
			return Naming{}, err
		}
		*p.dst = v
	}

	// The three listeners are separate sockets; two of them sharing a number
	// means the second bind fails at startup with nothing to explain it.
	seen := map[int]string{}
	for _, p := range []struct {
		key   string
		value int
	}{
		{"dns_port", n.DNSPort},
		{"http_port", n.HTTPPort},
		{"https_port", n.HTTPSPort},
	} {
		if other, dup := seen[p.value]; dup {
			return Naming{}, fmt.Errorf(
				"names.%s and names.%s are both %d; each listener needs its own port: %w",
				other, p.key, p.value, ErrInvalid)
		}
		seen[p.value] = p.key
	}

	return n, nil
}

// resolveNamingPort applies the default for an unset port and rejects any
// value the program could not bind or would refuse to bind.
func resolveNamingPort(key string, value, def int) (int, error) {
	if value == 0 {
		return def, nil
	}
	if value < 0 || value > 65535 {
		return 0, fmt.Errorf("names.%s = %d is not a port number (1-65535): %w", key, value, ErrInvalid)
	}
	if value < lowestUnprivilegedPort {
		return 0, fmt.Errorf(
			"names.%s = %d is a port the operating system reserves for privileged processes, "+
				"and quic-link never asks for that privilege; choose a port of %d or above "+
				"(the default is %d): %w",
			key, value, lowestUnprivilegedPort, def, ErrInvalid)
	}
	return value, nil
}

// resolveSuffix normalizes and checks the DNS suffix quic-link answers for.
//
// The check is stricter than it looks necessary, because this value ends up in
// the system's resolver configuration: every lookup underneath it on the whole
// machine is redirected here. A suffix of "." redirects everything; a suffix
// that is a real top-level domain redirects that entire namespace. Neither can
// be caught later, so both are caught now.
func resolveSuffix(raw string, isMine bool) (string, error) {
	if raw == "" {
		return DefaultSuffix, nil
	}
	if strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("names.suffix %q has leading or trailing whitespace: %w", raw, ErrInvalid)
	}

	s := strings.ToLower(raw)
	s = strings.TrimSuffix(s, ".") // a trailing dot is a valid way to spell a full name

	if s == "" {
		return "", fmt.Errorf(
			"names.suffix is the DNS root, which would send every lookup on this machine "+
				"to quic-link; use %q or a domain you control: %w",
			DefaultSuffix, ErrInvalid)
	}
	if len(s) > 253 {
		return "", fmt.Errorf("names.suffix is %d characters; the limit is 253: %w", len(s), ErrInvalid)
	}

	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return "", fmt.Errorf(
				"names.suffix %q is not a hostname: %q is not a valid label "+
					"(letters, digits and dashes, not starting or ending with a dash): %w",
				raw, l, ErrInvalid)
		}
	}

	// `arpa` is IANA infrastructure — `in-addr.arpa` and `ip6.arpa` under it are
	// how every host on the internet does reverse lookups. Nobody can own it, so
	// the "I control this domain" escape hatch is the wrong gate: refuse it and
	// everything beneath it outright. `home.arpa` is the one carve-out, because
	// it is set aside for exactly this purpose.
	if (s == "arpa" || strings.HasSuffix(s, ".arpa")) && !isReservedSuffix(s) {
		return "", fmt.Errorf(
			"names.suffix %q is under the infrastructure zone that reverse DNS lives in, "+
				"which nobody can control; use %q, or %q if you want a name of that shape: %w",
			s, DefaultSuffix, "home.arpa", ErrInvalid)
	}

	switch s {
	case "local":
		return "", fmt.Errorf(
			"names.suffix %q belongs to multicast DNS, which the operating system already "+
				"answers for; taking it over would break local device discovery. Use %q: %w",
			s, DefaultSuffix, ErrInvalid)
	case "localhost":
		return "", fmt.Errorf(
			"names.suffix %q is handled specially by resolvers and must keep pointing at this "+
				"machine. Use %q: %w",
			s, DefaultSuffix, ErrInvalid)
	}

	if isReservedSuffix(s) || isMine {
		return s, nil
	}

	return "", fmt.Errorf(
		"names.suffix %q is not a name reserved for private use, and quic-link would register "+
			"it with the system resolver — every lookup ending in %q on this machine would be "+
			"answered here. Use %q (the default, reserved for private use), or set "+
			"names.suffix_is_mine = true if you control %q and mean this: %w",
		s, s, DefaultSuffix, s, ErrInvalid)
}

// isReservedSuffix reports whether s is a name reserved for private use, or
// sits underneath one. "internal" and "lab.internal" both qualify; "internals"
// does not, because the comparison is anchored at a label boundary.
func isReservedSuffix(s string) bool {
	for _, r := range reservedSuffixes {
		if s == r || strings.HasSuffix(s, "."+r) {
			return true
		}
	}
	return false
}

// FlagOnlyServerName is the key a verb uses when it assembles a server purely
// from command-line flags, so that the settings the command will actually use
// are checked the same way a configured server would be.
//
// It is deliberately not a hostname. Such a server exists for the duration of
// one command, is never registered anywhere, and never has a name to resolve.
// The parentheses cannot collide with a real server either, because
// ValidateServerName refuses them for everything else — the exemption below is
// safe precisely because the rule it sidesteps is what makes the name
// unreachable for anybody else.
const FlagOnlyServerName = "(flags)"

// ValidateServerName checks that a server's name can be used as the leftmost
// label of a hostname, because that is what it becomes: a server called
// "server1" is reachable as "server1.<suffix>".
//
// This is stricter than the rule that applied when a server name was only a
// local label, so a name that was previously accepted may now be refused. That
// is deliberate and the message says what to do about it.
func ValidateServerName(name string) error {
	if name == "" {
		return fmt.Errorf("server name must not be empty")
	}
	if name == FlagOnlyServerName {
		return nil
	}
	if dnsLabel.MatchString(name) {
		return nil
	}
	if strings.ToLower(name) != name {
		return fmt.Errorf(
			"server name %q must be lowercase: it becomes the first part of a hostname, "+
				"and hostnames are compared without regard to case", name)
	}
	if len(name) > 63 {
		return fmt.Errorf("server name %q is %d characters; a hostname label may be at most 63", name, len(name))
	}
	return fmt.Errorf(
		"server name %q cannot be part of a hostname: use lowercase letters, digits and "+
			"dashes, not starting or ending with a dash", name)
}
