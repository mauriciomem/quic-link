package control

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestAuditName_RemovesEverythingThatCanChangeHowALineReads is a unit test on
// purpose, and specifically not an end-to-end one.
//
// This runs on a name a caller chose, before anything has validated it — that
// is the whole reason it exists. Driven end to end, most of these inputs never
// arrive: the name is refused earlier, for being a bad hostname, so a test at
// that level passes whether or not this function does anything at all. The only
// way to hold this function to its own claim is to call it.
func TestAuditName_RemovesEverythingThatCanChangeHowALineReads(t *testing.T) {
	cases := []struct {
		name string
		bad  string
		why  string
	}{
		{"a newline", "\n", "would forge a second line"},
		{"a carriage return", "\r", "would forge a second line"},
		{"an escape", "\x1b", "gives an escape sequence its framing"},
		{"a bell", "\x07", "terminates an operating-system command sequence"},
		{"a C1 control", "\u0085", "is a line break to some readers"},
		{"a bidi override", "\u202e", "makes honest text render in a misleading order"},
		{"a zero-width joiner", "\u200d", "hides a boundary between characters"},
		{"a line separator", "\u2028", "is neither a control nor a format character, and is a line break to some readers"},
		{"a paragraph separator", "\u2029", "same, and is missed by a check written against control and format characters alone"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := auditName("before" + c.bad + "after")
			if strings.Contains(got, c.bad) {
				t.Errorf("auditName kept %q, which %s: %q", c.bad, c.why, got)
			}
			// The readable content must survive, or a sanitiser that destroyed
			// everything would pass the assertion above and tell an operator
			// nothing.
			if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
				t.Errorf("auditName destroyed the readable part of the name: %q", got)
			}
		})
	}
}

// TestAuditName_IsBoundedAndAlwaysValidUTF8 covers the two properties a log
// writer depends on. The bound is what stops one refused call writing as much of
// a caller's own text as the caller likes; validity is what stops a bound landing
// mid-character and leaving a broken sequence in the middle of a line.
func TestAuditName_IsBoundedAndAlwaysValidUTF8(t *testing.T) {
	cases := map[string]string{
		"a long plain name":          strings.Repeat("a", 4000),
		"long multi-byte characters": strings.Repeat("\u2500", 600),
		"a truncated sequence":       strings.Repeat("a", 127) + "\u2500",
		"invalid bytes":              "ab\xffcd",
		"an overlong encoding":       "ab\xc0\xafcd",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := auditName(in)
			if len(got) > maxAuditedNameLen {
				t.Errorf("auditName returned %d bytes, over the %d-byte bound", len(got), maxAuditedNameLen)
			}
			if !utf8.ValidString(got) {
				t.Errorf("auditName returned invalid UTF-8: %q", got)
			}
		})
	}
}
