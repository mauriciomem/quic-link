package main

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// serverSpecList collects repeated NAME=VALUE flags that define servers on the
// command line, so a daemon can run with no settings file at all.
//
// It follows the shape the agent already uses for its own repeatable table
// flags: one flag, one key, one value, checked as it is parsed so a mistake is
// reported against the value the user typed rather than as a puzzle further in.
type serverSpecList struct {
	// flag is the flag's own name, used only so a message can quote the flag
	// the user actually typed.
	flag   string
	values map[string]string
}

// String renders the collected pairs for help output only.
func (l *serverSpecList) String() string {
	if len(l.values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l.values))
	for k := range l.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + l.values[k]
	}
	return strings.Join(parts, ",")
}

// Set parses one NAME=VALUE pair. The name is checked here because it becomes
// part of a hostname, and finding that out at startup is better than finding it
// out when a lookup fails.
func (l *serverSpecList) Set(v string) error {
	name, value, found := strings.Cut(v, "=")
	if !found {
		return fmt.Errorf("invalid --%s value %q: expected NAME=VALUE", l.flag, v)
	}
	if name == "" {
		return fmt.Errorf("invalid --%s value %q: the server name must not be empty", l.flag, v)
	}
	if value == "" {
		return fmt.Errorf("invalid --%s value %q: the value must not be empty", l.flag, v)
	}
	if err := config.ValidateServerName(name); err != nil {
		return fmt.Errorf("invalid --%s value %q: %v", l.flag, v, err)
	}
	if l.values == nil {
		l.values = make(map[string]string)
	}
	if existing, ok := l.values[name]; ok {
		return fmt.Errorf("duplicate --%s for %q (already set to %q)", l.flag, name, existing)
	}
	l.values[name] = value
	return nil
}

// Type returns the pflag value type name.
func (l *serverSpecList) Type() string { return "spec" }

// applyServerFlags replaces the settings file's servers with the ones given on
// the command line, and reports whether it did.
//
// Replacing rather than merging is deliberate. Somebody naming one server means
// that server, and merging would hand them their whole configured fleet as well
// — every session dialled, every port bound, every name answered. The flag that
// carries a pin already works this way for the same reason: a list that grants
// something should not quietly inherit entries nobody asked for. Only the server
// table is replaced; a suffix, an identity key path and log settings still come
// from the file, because none of those is what the user overrode.
//
// The replaced entries are named on the way past. A silent substitution would
// leave somebody who had forgotten a file existed looking at a fleet they could
// not explain.
func applyServerFlags(cfg *config.Config, addrs, pins *serverSpecList, configPath string) error {
	if len(addrs.values) == 0 && len(pins.values) == 0 {
		return nil
	}

	// A pin without an address names a server that does not exist. Accepting it
	// silently would leave the user believing they had defined something.
	for name := range pins.values {
		if _, ok := addrs.values[name]; !ok {
			return usageErrorf(
				"--server-pin names %q, but no --server-add defines it; give both for each server",
				name)
		}
	}
	for name := range addrs.values {
		if _, ok := pins.values[name]; !ok {
			return usageErrorf(
				"--server-add names %q, but no --server-pin gives its pin; a server cannot be "+
					"reached without one, since the pin is what proves which key answered",
				name)
		}
	}

	// The pin is parsed here as well as by validation, so the message names the
	// flag rather than a settings key the user never wrote.
	for name, pin := range pins.values {
		if _, err := identity.ParsePin(pin); err != nil {
			return usageErrorf("invalid --server-pin for %q: %v", name, err)
		}
	}

	if replaced := serverNameList(cfg.Servers); len(cfg.Servers) > 0 {
		slog.Warn("server flags replace the servers in your settings file",
			"role", "daemon", "file", config.FileInUse(configPath),
			"ignored", len(cfg.Servers), "ignored_servers", replaced)
	}

	built := make(map[string]config.Server, len(addrs.values))
	for name, addr := range addrs.values {
		built[name] = config.Server{Addr: addr, Pin: pins.values[name]}
	}
	cfg.Servers = built
	return nil
}

// describeMinimumViableRun explains what a daemon needs when it has been given
// nothing to manage.
//
// Starting with an empty pool and saying nothing was the unhelpful case: the
// naming sockets came up, the local API answered, and not one tunnel existed,
// which looks identical to a misconfiguration from outside. Either way of
// defining a server is offered, because both are supported ways to run and
// naming only one of them would be wrong for half the people who read it.
func describeMinimumViableRun(configPath string) string {
	return "no servers to manage: nothing was given on the command line and " +
		config.FileInUse(configPath) + " defines none.\n\n" +
		"  Either add an entry to that file:\n\n" +
		"    [servers.web1]\n" +
		"    addr = \"host:port\"\n" +
		"    pin  = \"<the agent's pin>\"\n\n" +
		"  or give one here:\n\n" +
		"    quic-link daemon --server-add web1=host:port --server-pin web1=<the agent's pin>\n\n" +
		"  The pin is printed by 'quic-link keygen' on the machine running the agent."
}
