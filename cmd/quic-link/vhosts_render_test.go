package main

// What a person sees, and what a script parses. The agent supplies these
// strings, and pinning proves which key answered rather than what its holder
// chose to put in a field, so both renderings run everything through the same
// sanitiser and neither branches on agent-chosen text.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/daemon"
)

func TestVhostRenderingStripsWhatAnAgentCouldSend(t *testing.T) {
	hostile := []daemon.VhostInfo{{
		Host:       "evil\r\nnames published by \"other\":\x1b]0;title\x07",
		Address:    "tcp://127.0.0.1:1\x1b[31m",
		Provenance: "config\x00",
	}}

	got := sanitizeVhosts(hostile)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	for _, field := range []string{got[0].Host, got[0].Address, got[0].Provenance} {
		if strings.ContainsAny(field, "\r\n") {
			t.Errorf("a field still carries a line break, so it can forge a line of output: %q", field)
		}
		if strings.ContainsRune(field, '\x1b') {
			t.Errorf("a field still carries an escape, so it can act on the terminal: %q", field)
		}
		if strings.ContainsRune(field, '\x00') {
			t.Errorf("a field still carries a control byte: %q", field)
		}
	}

	// One line per entry, whatever the entry contains. That is the property the
	// stripping buys: a field cannot introduce a line, so it cannot forge one.
	// It does not buy protection against text that merely reads like a heading —
	// the sanitiser removes control bytes and bounds length, and the route
	// listing that shipped first has the same property. Anything more would mean
	// deciding which words an agent is allowed to use in a name.
	var out bytes.Buffer
	printVhostsHuman(&out, "srv", got)
	if lines := strings.Count(strings.TrimRight(out.String(), "\n"), "\n"); lines != 1 {
		t.Errorf("a hostile name changed the line count: want a header and one entry, got %d "+
			"line breaks:\n%q", lines, out.String())
	}
}

// TestTheOriginLabelIsChosenHereNotByTheAgent is the point of originLabel. The
// provenance string arrives from the far end; if it were printed as prose, a
// compromised agent would choose the sentence a person reads.
func TestTheOriginLabelIsChosenHereNotByTheAgent(t *testing.T) {
	cases := map[string]string{
		"runtime": "published while running",
		"config":  "from configuration",
		"builtin": "builtin",
	}
	for provenance, want := range cases {
		if got := originLabel(provenance); got != want {
			t.Errorf("provenance %q renders as %q, want %q", provenance, got, want)
		}
	}

	// The set is open, so an unfamiliar value is not an error — but it must not
	// be passed through as the words on the page either.
	weird := originLabel("something-new-from-a-newer-agent")
	if strings.Contains(weird, "something-new") {
		t.Errorf("an unrecognised provenance is printed verbatim, letting the agent choose the "+
			"wording: %q", weird)
	}
	if weird == "" {
		t.Error("an unrecognised provenance renders as nothing, so a reader cannot tell it apart")
	}
}

// TestBothRenderingsCarrySanitisedFields: a --json consumer that decodes and
// prints a field raw is exposed to the same bytes the human path is, so the
// sanitiser cannot be skipped on either route.
func TestBothRenderingsCarrySanitisedFields(t *testing.T) {
	in := []daemon.VhostInfo{{Host: "a\x1b]0;x\x07.internal", Address: "tcp://127.0.0.1:1", Provenance: "runtime"}}
	got := sanitizeVhosts(in)

	out := vhostsJSONOutput{Schema: 1, Server: "srv", Vhosts: got}
	if strings.ContainsRune(out.Vhosts[0].Host, '\x1b') {
		t.Errorf("the machine-readable shape carries an escape: %q", out.Vhosts[0].Host)
	}

	var human bytes.Buffer
	printVhostsHuman(&human, "srv", got)
	if strings.ContainsRune(human.String(), '\x1b') {
		t.Errorf("the human rendering carries an escape:\n%q", human.String())
	}
}

// TestAnAgentPublishingNothingSaysSo covers the empty answer, which must read as
// an answer rather than as a missing one.
func TestAnAgentPublishingNothingSaysSo(t *testing.T) {
	var out bytes.Buffer
	printVhostsHuman(&out, "srv", nil)
	if !strings.Contains(out.String(), "publishes no names") {
		t.Errorf("an agent with no names produces no readable answer: %q", out.String())
	}
}
