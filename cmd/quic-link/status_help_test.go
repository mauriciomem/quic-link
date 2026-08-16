package main

// The published command reference says the CLI's own help output is the final
// word on these shapes, which makes that text the only public statement of the
// status document's contract. It had fallen a version behind the document the
// daemon actually produces, and nothing noticed, because the normative prose
// lives outside the source tree where no test can read it.
//
// These checks close that gap from the inside: the version in the help text is
// compared against a document really built by the code, and every word the
// route field can carry must be named there.

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/daemon"
)

// statusLongHelp returns the status verb's own description, as a user reading
// --help would see it.
func statusLongHelp(t *testing.T) string {
	t.Helper()
	for _, c := range newRootCmd().Commands() {
		if c.Name() == "status" {
			return c.Long
		}
	}
	t.Fatal("the status verb is not registered, so its help text cannot be checked")
	return ""
}

// TestStatusHelpNamesTheVersionItActuallyEmits takes the version from a document
// the code really produces rather than from a constant, so the two cannot drift
// apart without this failing.
func TestStatusHelpNamesTheVersionItActuallyEmits(t *testing.T) {
	noSidecar := func(string) (time.Time, bool, error) { return time.Time{}, false, nil }
	snap := daemon.BuildSnapshot(nil, daemon.WallClock{}, "", 0, noSidecar)

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Schema == 0 {
		t.Fatal("the status document reports no version, so there is nothing to compare")
	}

	want := `{"schema":` + strconv.Itoa(doc.Schema)
	if !strings.Contains(statusLongHelp(t), want) {
		t.Errorf("the status help does not describe the version the daemon emits (%s); the "+
			"published reference defers to this text, so it is the only public statement of "+
			"the shape and a stale one is worse than none", want)
	}
}

// TestStatusHelpNamesEveryRouteWord requires the whole vocabulary to be visible
// where a user can read it, including the words that are not emitted yet — that
// is the point of naming them early.
func TestStatusHelpNamesEveryRouteWord(t *testing.T) {
	help := statusLongHelp(t)
	for _, word := range []string{
		"ipv4-direct", "ipv6-direct", "router-mapped", "punched", "bound-proxy", "relayed",
	} {
		if !strings.Contains(help, word) {
			t.Errorf("the status help does not name the route %q; the vocabulary is published so a "+
				"reader can tell a word they do not recognise from a fault", word)
		}
	}
	for _, field := range []string{`"path"`, `"last_error"`} {
		if !strings.Contains(help, field) {
			t.Errorf("the status help does not mention the %s field, which the document emits", field)
		}
	}
}
