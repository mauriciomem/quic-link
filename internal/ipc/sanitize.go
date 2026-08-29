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
// It strips every C0 control byte (0x00-0x1F, which includes ESC, BEL, CR
// and LF — the bytes that give a terminal escape or OSC sequence its
// structure, and the two that could forge a second log line), every C1
// control byte (0x7F-0x9F), every Unicode format character (category Cf,
// e.g. U+202E RIGHT-TO-LEFT OVERRIDE) and every line/paragraph separator
// (Zl/Zp) missed by the two checks above. It drops any byte sequence that is
// not valid UTF-8 rather than replacing it, so a run of garbage cannot
// inflate the output, and it truncates the result to MaxSanitizedFieldLen
// bytes.
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
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			// C0 and C1 control bytes: the framing an escape or OSC
			// sequence needs, and the CR/LF that would forge a second line.
		case unicode.Is(unicode.Cf, r):
			// Unicode format characters: no framing power over an escape
			// sequence or JSON syntax, but the whole point of one (like a
			// bidi override) is to make already-honest bytes render in a
			// different, misleading order.
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			// Line and paragraph separators, which are neither control nor
			// format characters and so are missed by both cases above. A
			// consumer that treats one as a line break reads output as
			// having more lines than were written.
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
