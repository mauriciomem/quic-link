package edge

import "strings"

import "testing"

// TestSafeHostForLog_CannotForgeALogLine pins the defence on the one string in
// this path that an unknown client chooses. The check that turns requests away
// is reached by whatever anybody sends, and it now says so at a level an
// operator sees, so the name it reports must not be able to write a second line
// or steer whatever is reading the log.
func TestSafeHostForLog_CannotForgeALogLine(t *testing.T) {
	cases := map[string]string{
		"a.internal":        "a.internal",
		"":                  "(none)",
		"a\r\nlevel=INFO":   "a??level=INFO",
		"a\x00b":            "a?b",
		"a\x1b[31mred":      "a?[31mred",
		"a\x7fb":            "a?b",
		"caf\xc3\xa9.local": "caf??.local",
	}
	for in, want := range cases {
		if got := safeHostForLog(in); got != want {
			t.Errorf("safeHostForLog(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSafeHostForLog_IsBounded pins that a long name cannot fill a log. A real
// hostname cannot reach this length, so anything that does is not a name and
// there is no reason to repeat all of it.
func TestSafeHostForLog_IsBounded(t *testing.T) {
	got := safeHostForLog(strings.Repeat("a", 4096))
	if len(got) > maxLoggedHostLen+3 {
		t.Errorf("logged host is %d bytes, want it cut to at most %d plus a marker",
			len(got), maxLoggedHostLen)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a cut name must say it was cut, got %q", got)
	}
}
