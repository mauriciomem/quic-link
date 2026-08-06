// Package names owns the client-side naming layer: which hostnames this
// machine answers for, and what they mean.
//
// Everything here works on names alone. Nothing in this package opens a
// session, consults a pool, or knows whether a server is reachable — a name
// resolving and a service being up are different questions, answered by
// different layers. Keeping them apart is what lets a browser report "cannot
// connect" instead of "cannot resolve" when a server is merely down.
package names

import (
	"sort"
	"strings"
	"sync"
)

// Zone is the set of names this machine answers for: one suffix and the
// servers underneath it. It is built once and never changes; a configuration
// change means a new daemon.
type Zone struct {
	suffix  string
	servers map[string]struct{}

	mu     sync.Mutex
	probes map[string]struct{}
}

// ProbeLabel is the label that marks a name as a check rather than a real
// lookup. A name under it is answered like any other and its label is
// remembered, which is what lets the diagnosis verb prove the system resolver
// really reached this responder — rather than merely that some answer came
// back, which a stale cache or a hosts entry would also produce.
const ProbeLabel = "_probe"

// noteProbe remembers that a check was seen.
func (z *Zone) noteProbe(label string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.probes == nil {
		z.probes = make(map[string]struct{})
	}
	// Keep only a handful: this is a latch for a check that runs seconds later,
	// not a log.
	if len(z.probes) > 64 {
		z.probes = make(map[string]struct{})
	}
	z.probes[label] = struct{}{}
}

// SawProbe reports whether a check with this label reached the responder, and
// forgets it so the same label cannot answer twice.
func (z *Zone) SawProbe(label string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	_, ok := z.probes[label]
	delete(z.probes, label)
	return ok
}

// NewZone builds a zone from a validated suffix and the names of the servers
// that are actually managed. Both are expected to be lowercase already —
// configuration validation guarantees it — but the constructor lowercases
// anyway so a caller that skips validation cannot produce a zone that silently
// never matches.
func NewZone(suffix string, servers []string) *Zone {
	z := &Zone{
		suffix:  strings.ToLower(strings.TrimSuffix(suffix, ".")),
		servers: make(map[string]struct{}, len(servers)),
		probes:  make(map[string]struct{}),
	}
	for _, s := range servers {
		if s == "" {
			continue
		}
		z.servers[strings.ToLower(s)] = struct{}{}
	}
	return z
}

// Suffix returns the zone's suffix, lowercase and without a trailing dot.
func (z *Zone) Suffix() string { return z.suffix }

// Servers returns the managed server names in a stable order.
func (z *Zone) Servers() []string {
	out := make([]string, 0, len(z.servers))
	for s := range z.servers {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// InSuffix reports whether host sits inside this zone. host must already be
// lowercase and free of a trailing dot.
//
// The comparison is anchored at a label boundary, and that anchoring is the
// whole point: a test that merely asked whether the name *contains* or *ends
// with* the suffix would accept `notinternal` and `internal.evil.example`,
// which is exactly the hole this check exists to close.
func (z *Zone) InSuffix(host string) bool {
	if z.suffix == "" {
		return false
	}
	return host == z.suffix || strings.HasSuffix(host, "."+z.suffix)
}

// Split takes a host inside the zone and reports which server it belongs to
// and which service on that server, with the suffix removed.
//
// `grafana.server1.internal` is service `grafana` on server `server1`.
// `server1.internal` is server `server1` with no service. The zone's own name
// belongs to no server and reports ok=false, as does anything outside it.
//
// A service may itself be several labels (`a.b.server1.internal` is service
// `a.b`); the server is always the single label immediately before the suffix.
func (z *Zone) Split(host string) (server, service string, ok bool) {
	if !z.InSuffix(host) || host == z.suffix {
		return "", "", false
	}
	prefix := strings.TrimSuffix(host, "."+z.suffix)
	if prefix == "" {
		return "", "", false
	}
	i := strings.LastIndex(prefix, ".")
	if i < 0 {
		return prefix, "", true
	}
	server, service = prefix[i+1:], prefix[:i]
	if server == "" || service == "" {
		// A leading or doubled dot: not a hostname.
		return "", "", false
	}
	return server, service, true
}

// Manages reports whether the named server is one this machine looks after.
func (z *Zone) Manages(server string) bool {
	_, ok := z.servers[server]
	return ok
}
