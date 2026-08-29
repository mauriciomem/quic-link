package daemon

import (
	"errors"
	"strings"
	"testing"
)

// TestBoundedFailureText_StripsLineAndParagraphSeparators is the regression
// test for the gap the audit found: boundedFailureText handled C0/C1
// controls, the Cf format category, and \n/\r/\t, but not the Unicode
// Zl/Zp line- and paragraph-separator categories (U+2028, U+2029) — the
// exact two runes internal/ipc.SanitizeAgentString's fourth case exists to
// catch, because a reader that treats one as a line break sees output with
// more lines than were actually written. LastError can carry a QUIC
// ApplicationError/TransportError whose Error() interpolates a
// CONNECTION_CLOSE reason phrase chosen by the far end, so this text is not
// first-party and must be held to the same rule as every other
// far-end-worded field.
func TestBoundedFailureText_StripsLineAndParagraphSeparators(t *testing.T) {
	in := "forged\u2028second line\u2029third"
	got := boundedFailureText(in)
	if strings.ContainsRune(got, '\u2028') {
		t.Errorf("boundedFailureText(%q) = %q, want U+2028 stripped", in, got)
	}
	if strings.ContainsRune(got, '\u2029') {
		t.Errorf("boundedFailureText(%q) = %q, want U+2029 stripped", in, got)
	}
}

// TestDialFailureText_StripsLineAndParagraphSeparators exercises the public
// entry point one level up, so the property holds on the value that
// actually reaches SessionState.LastError and, from there, the status
// document — not merely on the internal helper.
func TestDialFailureText_StripsLineAndParagraphSeparators(t *testing.T) {
	err := errors.New("mem: conn closed with code 2: forged\u2028second line\u2029third")
	got := dialFailureText(stateConnecting, err)
	if strings.ContainsRune(got, '\u2028') || strings.ContainsRune(got, '\u2029') {
		t.Errorf("dialFailureText(...) = %q, want U+2028/U+2029 stripped", got)
	}
}
