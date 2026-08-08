package main

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mauriciomem/quic-link/internal/daemon"
)

// maxAgentFieldLen bounds how much of a single agent-controlled string (a
// route's target name or address, as reported live by "status --routes") is
// ever rendered, in either TTY or --json output. It is generous for any
// real route — router.ValidateRouteName caps a legitimate route name at 64
// bytes, and a real address is a short host:port or unix path — so this
// bound is purely defence against a compromised-but-pinned agent using its
// GetStatus reply as an amplification vector against the CLI's own output
// (a multi-megabyte "route name" flooding a terminal or a script's parser).
const maxAgentFieldLen = 256

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
// It strips every C0 control byte (0x00-0x1F, which includes ESC, BEL, CR
// and LF), every C1 control byte (0x7F-0x9F, which includes DEL and the
// single-byte 8-bit form some terminals accept as an escape introducer),
// and every Unicode format character (category Cf — e.g. U+202E RIGHT-TO-
// LEFT OVERRIDE and its relatives). A format character is valid UTF-8 and
// cannot forge a newline or break JSON syntax, so it is not a script- or
// escape-injection vector; its entire purpose is to change how
// already-rendered text visually reorders on screen, which is exactly
// enough for a hostile agent to make an honest route address *look* like
// something else to whoever is reading a terminal, even though the
// underlying bytes never lied. Stripping it means the human-visible
// rendering can never be made to lie, at no cost to any legitimate route
// name, which never contains one. It also drops any byte sequence that is
// not valid UTF-8, and truncates the result to maxAgentFieldLen bytes.
//
// Deliberately NOT special-cased: recognising and stripping specific escape
// *sequences* (e.g. "ESC ] ... BEL" for OSC) would be an allow-list-shaped
// defense that has to be extended every time a terminal emulator adds a new
// sequence grammar. Removing the control bytes that give any such sequence
// its structure is a strictly smaller, complete defense: whatever printable
// text remains (e.g. "]0;pwned" from an OSC payload) renders as inert
// literal text, because the terminal never sees the ESC/BEL bytes that would
// have made it act as a command.
//
// Whether to sanitise --json too, or rely solely on encoding/json's own
// escaping, is a deliberate call, not a default: json.Marshal correctly
// escapes control bytes so the JSON *document itself* stays syntactically
// valid and a forged value can never break out of its string context or
// forge a new key. But a downstream tool that decodes that JSON and prints
// a field's value raw (`jq -r '.routes[].target'` piped straight to a
// terminal, or a shell `eval`) would still be exposed to whatever bytes
// were inside the string — encoding/json only protects the JSON layer, not
// whatever the next tool in a pipeline does with the decoded value.
// Machine-readable output is a contract other programs build on, so this
// function is applied identically before both the TTY renderer and the
// --json marshaller; there is exactly one sanitisation boundary, not two.
func sanitizeAgentString(s string) string {
	truncated := false
	if len(s) > maxAgentFieldLen {
		s = s[:maxAgentFieldLen]
		truncated = true
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Not valid UTF-8 at this position. Drop the byte rather than
			// emit a replacement character per bad byte, which would let a
			// long run of garbage inflate the output instead of shrinking it.
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			// C0 and C1 control bytes: the framing an escape or OSC
			// sequence needs, and the CR/LF that would forge a second line.
		case unicode.Is(unicode.Cf, r):
			// Unicode format characters: no framing power over an escape
			// sequence or JSON syntax, but the whole point of one (like a
			// bidi override) is to make already-honest bytes render in a
			// different, misleading order.
		default:
			b.WriteRune(r)
		}
		i += size
	}

	out := b.String()
	if truncated {
		out += "...[truncated]"
	}
	return out
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
}

// sanitizeRoutes converts a daemon-relayed route list to the CLI's
// sanitized shape, running every agent-controlled field through
// sanitizeAgentString exactly once.
func sanitizeRoutes(in []daemon.RouteInfo) []sanitizedRoute {
	out := make([]sanitizedRoute, len(in))
	for i, r := range in {
		out[i] = sanitizedRoute{
			Target:  sanitizeAgentString(r.Target),
			Address: sanitizeAgentString(r.Address),
			Builtin: r.Builtin,
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
