package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/daemon"
)

// TestSanitizeAgentString_StripsOSCInjection proves an OSC title-bar-rewrite
// escape sequence — a route named "grafana\x1b]0;pwned\x07", as a
// compromised-but-still-pinned agent could report it — is rendered inert:
// the ESC (0x1B) and BEL (0x07) bytes that give the sequence its structure
// are gone, and the remaining printable payload survives only as ordinary
// text a terminal cannot act on. This is the most important test of the
// sanitiser: the escape's *framing* bytes, not the printable characters
// inside it, are what a terminal actually interprets.
func TestSanitizeAgentString_StripsOSCInjection(t *testing.T) {
	hostile := "grafana\x1b]0;pwned\x07"
	got := sanitizeAgentString(hostile)

	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("sanitized output still contains ESC (0x1B): %q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("sanitized output still contains BEL (0x07): %q", got)
	}
	const want = "grafana]0;pwned"
	if got != want {
		t.Errorf("sanitizeAgentString(%q) = %q, want %q", hostile, got, want)
	}
}

// TestSanitizeAgentString_StripsEmbeddedNewline proves an embedded LF cannot
// forge a second, well-formed line in TTY output — the concrete
// script-forgery risk that matters most for a --json line a downstream
// tool reads one line at a time, and one that also matters for the
// human-readable renderer.
func TestSanitizeAgentString_StripsEmbeddedNewline(t *testing.T) {
	hostile := "ssh\nfake-route forged=true"
	got := sanitizeAgentString(hostile)

	if strings.ContainsRune(got, '\n') {
		t.Errorf("sanitized output still contains an embedded newline: %q", got)
	}
	const want = "sshfake-route forged=true"
	if got != want {
		t.Errorf("sanitizeAgentString(%q) = %q, want %q", hostile, got, want)
	}
}

// TestSanitizeAgentString_StripsCarriageReturn proves a raw CR (a classic
// terminal trick for overwriting an already-printed line) is stripped, not
// merely a paired CRLF.
func TestSanitizeAgentString_StripsCarriageReturn(t *testing.T) {
	hostile := "ssh\rDOCKER_HOST forged"
	got := sanitizeAgentString(hostile)

	if strings.ContainsRune(got, '\r') {
		t.Errorf("sanitized output still contains a raw CR: %q", got)
	}
	const want = "sshDOCKER_HOST forged"
	if got != want {
		t.Errorf("sanitizeAgentString(%q) = %q, want %q", hostile, got, want)
	}
}

// TestSanitizeAgentString_StripsBidiOverride proves a Unicode format
// character (U+202E RIGHT-TO-LEFT OVERRIDE, paired here with U+202C POP
// DIRECTIONAL FORMATTING) is removed even though it is valid UTF-8 and has
// no power to forge a newline or break JSON syntax — its only purpose is to
// visually reorder already-rendered text, which would let a hostile agent
// make an honest route name render deceptively in a terminal without ever
// changing what the underlying bytes actually say.
func TestSanitizeAgentString_StripsBidiOverride(t *testing.T) {
	hostile := "ssh-\u202egnip\u202c-real" // renders as "ssh--realping" reversed if not stripped
	got := sanitizeAgentString(hostile)

	if strings.ContainsRune(got, '\u202e') || strings.ContainsRune(got, '\u202c') {
		t.Errorf("sanitized output still contains a bidi override/pop character: %q", got)
	}
	const want = "ssh-gnip-real"
	if got != want {
		t.Errorf("sanitizeAgentString(%q) = %q, want %q", hostile, got, want)
	}
}

// TestSanitizeAgentString_DropsInvalidUTF8 proves a byte sequence that is
// not valid UTF-8 does not reach the output verbatim (which would risk a
// downstream consumer's own decoder behaving unpredictably), and does not
// panic the rune-by-rune scan.
func TestSanitizeAgentString_DropsInvalidUTF8(t *testing.T) {
	hostile := "ssh-\xff\xfe-bad"
	got := sanitizeAgentString(hostile)

	if !utf8Valid(got) {
		t.Errorf("sanitized output is not valid UTF-8: %q", got)
	}
	const want = "ssh--bad"
	if got != want {
		t.Errorf("sanitizeAgentString(%q) = %q, want %q", hostile, got, want)
	}
}

// TestSanitizeAgentString_BoundsLength proves an extremely long agent string
// (roughly 1 MiB) is truncated rather than rendered or marshalled in full,
// bounding both terminal spam and the size of a --json document a
// compromised agent could force the CLI to produce.
func TestSanitizeAgentString_BoundsLength(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // ~1 MiB
	got := sanitizeAgentString(huge)

	if len(got) > maxAgentFieldLen+len("...[truncated]") {
		t.Errorf("sanitized output length = %d, want <= %d", len(got), maxAgentFieldLen+len("...[truncated]"))
	}
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Errorf("sanitized output does not indicate truncation: last 30 bytes = %q", lastN(got, 30))
	}
}

// TestSanitizeAgentString_LeavesOrdinaryRouteDataUnchanged proves the
// sanitiser is a no-op for the values a legitimate route already produces
// (router.ValidateRouteName's own character class plus a normal tcp:// or
// unix:// address) — sanitisation must never mangle honest output.
func TestSanitizeAgentString_LeavesOrdinaryRouteDataUnchanged(t *testing.T) {
	cases := []string{
		"ssh",
		"pg-app_01.internal",
		"tcp://127.0.0.1:5432",
		"unix:///var/run/docker.sock",
	}
	for _, s := range cases {
		if got := sanitizeAgentString(s); got != s {
			t.Errorf("sanitizeAgentString(%q) = %q, want unchanged", s, got)
		}
	}
}

// TestSanitizeRoutes_JSONOutputIsSafeForARawConsumer proves the --json
// rendering path: after sanitizeRoutes + json.Marshal, decoding the
// resulting document back out (as a naive downstream consumer piping a
// decoded string field to a terminal would) never reproduces the hostile
// escape bytes. This is the test for the explicit "--json is sanitised too"
// decision: json.Marshal's own escaping protects JSON *syntax*, not a
// downstream tool that decodes the string and prints it raw.
func TestSanitizeRoutes_JSONOutputIsSafeForARawConsumer(t *testing.T) {
	hostile := "grafana\x1b]0;pwned\x07"
	routes := sanitizeRoutes(hostileRouteInfos(hostile))

	out := routesJSONOutput{Schema: 1, Server: "srv1", Routes: routes}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// A raw byte-level check on the wire bytes: no literal ESC or BEL byte
	// anywhere in the document, sanitised or JSON-escaped.
	if strings.ContainsRune(string(b), 0x1b) || strings.ContainsRune(string(b), 0x07) {
		t.Fatalf("marshalled JSON contains a raw control byte: %q", b)
	}

	// Decode back out, simulating a consumer that reads the field as a Go
	// string (equivalent to `jq -r` printing it raw to a terminal) and
	// confirm the escape is still gone post-decode, not just hidden behind
	// JSON's own \u escaping.
	var decoded routesJSONOutput
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(decoded.Routes) != 1 {
		t.Fatalf("decoded %d routes, want 1", len(decoded.Routes))
	}
	got := decoded.Routes[0].Target
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Errorf("decoded target still contains a control byte: %q", got)
	}
}

// ---- test helpers -----------------------------------------------------------

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '\ufffd' {
			// Only meaningful if the source byte was actually invalid;
			// range over string already replaces invalid sequences with
			// U+FFFD, so encountering it here after our own sanitisation
			// (which drops invalid bytes instead of replacing them) would
			// indicate a real problem worth flagging.
			return false
		}
	}
	return true
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func hostileRouteInfos(target string) []daemon.RouteInfo {
	return []daemon.RouteInfo{{Target: target, Address: "tcp://127.0.0.1:1", Builtin: false}}
}

// TestSanitizeRoutes_ProvenanceIsSanitized covers the newest agent-controlled
// string on this boundary. Provenance is expected to be one of a small set of
// words, which is exactly why it is easy to forget it is still free text
// chosen by the far end: an agent that is correctly pinned but compromised can
// put anything at all in it, and pinning proves which key answered, not what
// that key's holder chose to send.
//
// The assertion is deliberately not "the output differs from the input" — a
// sanitiser that mangled every value would pass that. It checks that the
// specific dangerous bytes are gone and the readable part survives, so the
// test fails both if sanitisation is dropped and if it starts destroying
// legitimate values.
func TestSanitizeRoutes_ProvenanceIsSanitized(t *testing.T) {
	const hostile = "builtin\x1b]0;pwned\x07\r\nconfig\u202e"
	in := []daemon.RouteInfo{{
		Target:     "grafana",
		Address:    "tcp://127.0.0.1:3000",
		Builtin:    false,
		Provenance: hostile,
	}}

	got := sanitizeRoutes(in)
	if len(got) != 1 {
		t.Fatalf("sanitizeRoutes returned %d entries, want 1", len(got))
	}
	p := got[0].Provenance
	for _, bad := range []string{"\x1b", "\x07", "\r", "\n", "\u202e"} {
		if strings.Contains(p, bad) {
			t.Errorf("sanitized provenance still contains %q: %q", bad, p)
		}
	}
	if !strings.Contains(p, "builtin") {
		t.Errorf("sanitized provenance lost its readable content: %q", p)
	}
}

// TestPrintRoutesHuman_NeverRendersFromProvenance proves the human rendering
// decides what to print from the boolean, never from the agent's free-text
// provenance. A bool cannot carry an escape sequence or a lie about its own
// meaning; a string can. An agent that claims "builtin" for an entry the
// boolean says is not builtin must not be able to make this side agree.
func TestPrintRoutesHuman_NeverRendersFromProvenance(t *testing.T) {
	routes := []sanitizedRoute{{
		Target:     "grafana",
		Address:    "tcp://127.0.0.1:3000",
		Builtin:    false,
		Provenance: "builtin",
	}}
	var buf bytes.Buffer
	printRoutesHuman(&buf, "server1", routes)
	if strings.Contains(buf.String(), "(builtin)") {
		t.Errorf("human rendering trusted the agent's provenance string over the boolean:\n%s", buf.String())
	}
}
