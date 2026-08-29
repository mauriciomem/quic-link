package main

import (
	"fmt"
	"io"

	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// maxAgentFieldLen mirrors ipc.MaxSanitizedFieldLen under the name this
// package's own tests already know it by. It is kept as a separate constant
// rather than a direct alias reference in every call site so this file's
// tests can assert against a name local to the package being tested, but
// the two values are defined once, in internal/ipc, and must never drift:
// see sanitizeAgentString below.
const maxAgentFieldLen = ipc.MaxSanitizedFieldLen

// sanitizeAgentString renders an agent-controlled string safe to place in
// BOTH a human terminal and a --json document, before either the CLI's own
// Fprintf calls or encoding/json ever see it.
//
// The agent that answers GetStatus is authenticated by pinning, but pinning
// proves which key answered, not what that key's holder chooses to put in a
// route's target or address field — a compromised-but-still-correctly-pinned
// agent can return anything. This function is the CLI-side presentation
// boundary that assumes exactly that and defends against it; it must never
// run on the agent side, since the agent is precisely the party the threat
// model distrusts here.
//
// This is a thin wrapper over ipc.SanitizeAgentString, which is what
// actually strips control bytes, Unicode format characters, and invalid
// UTF-8, and bounds the result — see that function's doc for the full
// reasoning. The logic lives there, in a package both this CLI and the
// daemon-side IPC relay can import, so a compromised-but-pinned peer's
// wording is cleaned by exactly one implementation rather than two that
// could quietly drift apart. This wrapper exists only so the CLI's own
// call sites and tests keep the name they already use.
func sanitizeAgentString(s string) string {
	return ipc.SanitizeAgentString(s)
}

// sanitizedRoute is the CLI's own shape for one route entry, distinct from
// daemon.RouteInfo on purpose: nothing agent-controlled may reach a Printf
// or json.Marshal call before it has been through sanitizeAgentString, and
// keeping a separate type makes that ordering a compile-time property
// (there is no sanitizedRoute constructor that skips it) rather than a
// convention a future call site could forget.
type sanitizedRoute struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	Builtin bool   `json:"builtin"`
	// Provenance is agent-supplied free text like every other string here,
	// so it goes through the same sanitiser. It is reported but never
	// allowed to decide how anything renders: a compromised agent could
	// send any word at all, and the boolean above is the field this side
	// trusts for that, because a bool cannot carry an escape sequence.
	Provenance string `json:"provenance,omitempty"`
}

// sanitizeRoutes converts a daemon-relayed route list to the CLI's
// sanitized shape, running every agent-controlled field through
// sanitizeAgentString exactly once.
func sanitizeRoutes(in []daemon.RouteInfo) []sanitizedRoute {
	out := make([]sanitizedRoute, len(in))
	for i, r := range in {
		out[i] = sanitizedRoute{
			Target:     sanitizeAgentString(r.Target),
			Address:    sanitizeAgentString(r.Address),
			Builtin:    r.Builtin,
			Provenance: sanitizeAgentString(r.Provenance),
		}
	}
	return out
}

// routesJSONOutput is the --json shape "status --routes SERVER" prints. It
// mirrors daemon.RoutesSnapshot field for field, but every route it carries
// has already been through sanitizeRoutes — this type can only be built
// from already-sanitized data, by construction.
type routesJSONOutput struct {
	Schema int              `json:"schema"`
	Server string           `json:"server"`
	Routes []sanitizedRoute `json:"routes"`
}

// printRoutesHuman writes the free-form (anti-contract) human rendering of
// a server's sanitized route table. Every field it prints has already been
// through sanitizeAgentString, so no Fprintf call site here needs its own
// escaping logic.
func printRoutesHuman(w io.Writer, server string, routes []sanitizedRoute) {
	if len(routes) == 0 {
		fmt.Fprintf(w, "server %q reports no routes\n", server)
		return
	}
	fmt.Fprintf(w, "routes for %q:\n", server)
	for _, r := range routes {
		if r.Builtin {
			fmt.Fprintf(w, "  %-20s %-40s (builtin)\n", r.Target, r.Address)
		} else {
			fmt.Fprintf(w, "  %-20s %-40s\n", r.Target, r.Address)
		}
	}
}
