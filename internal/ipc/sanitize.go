package ipc

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxSanitizedFieldLen bounds how much of a single far-end-worded string
// this package's SanitizeAgentString ever keeps. It is generous for any
// legitimate value that crosses this boundary — a hostname label tops out at
// 253 bytes, and every RoutesError.Msg this tree constructs is a short,
// fixed-shape sentence — so the bound exists purely as defense against a
// correctly-pinned peer using its own wording as an amplification or
// terminal-flooding vector, not as a limit a real value could ever meet.
const MaxSanitizedFieldLen = 256

// IsUnsafeAgentRune reports whether r belongs to a Unicode category this
// package treats as unsafe to place in front of a human when it was chosen
// by the far end of a session: C0/C1 control characters (the framing an
// escape or OSC sequence needs, plus CR/LF), Unicode format characters
// (category Cf, e.g. a bidi override), and line/paragraph separators
// (Zl/Zp, missed by the control-character check because they are neither
// control nor format characters). It is the single definition of "unsafe"
// this package and internal/daemon build their sanitizers on:
// SanitizeAgentString below uses it directly, and internal/daemon's
// boundedFailureText consults it too, layering its own bound, truncation
// marker, and whitespace-to-space substitution on top.
//
// internal/control/addvhost.go's auditName solves the same problem for a
// caller-supplied name written to this agent's own log, and applies the
// identical five rune classes — but cannot call this function: this
// package already depends on internal/control (for the control-plane
// client), so importing the other way would cycle. Its own copy of the
// rule is deliberately kept in step by hand; a category added here is
// worth checking against auditName too.
func IsUnsafeAgentRune(r rune) bool {
	switch {
	case r < 0x20 || (r >= 0x7f && r <= 0x9f):
		return true
	case unicode.Is(unicode.Cf, r):
		return true
	case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		return true
	default:
		return false
	}
}

// SanitizeAgentString renders a string chosen by the far end of a session
// safe to place in front of a human, whether on a terminal or inside a --json
// document, before it leaves this trust boundary.
//
// Every RoutesError.Msg this package's own relays construct is either fixed,
// operator-facing prose this build wrote itself, or (at a handful of call
// sites in internal/daemon) a gRPC status message the connected agent
// worded. Being authenticated by pinning proves which key answered a
// handshake; it says nothing about what that key's holder chooses to put in
// a status message, an error string, or a published name — a correctly
// pinned peer that is nonetheless malicious can still shape that text
// freely. This function is the one place that distrust is acted on, so no
// relay that forwards far-end text can forget to.
//
// Character handling is IsUnsafeAgentRune, above. It drops any byte
// sequence that is not valid UTF-8 rather than replacing it, so a run of
// garbage cannot inflate the output, and it truncates the result to
// MaxSanitizedFieldLen bytes.
//
// Deliberately NOT special-cased: recognising specific escape *sequences*
// (e.g. "ESC ] ... BEL" for OSC) would be an allow-list-shaped defense that
// needs extending every time a terminal emulator grows a new sequence
// grammar. Removing the control bytes that give any such sequence its
// structure is a strictly smaller, complete defense — whatever printable
// text remains renders as inert literal text, because the terminal never
// sees the bytes that would have made it act as a command.
func SanitizeAgentString(s string) string {
	truncated := false
	if len(s) > MaxSanitizedFieldLen {
		s = s[:MaxSanitizedFieldLen]
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
		case IsUnsafeAgentRune(r):
			// See IsUnsafeAgentRune's own doc for which categories this covers.
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
