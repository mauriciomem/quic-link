package main

// The checks a person actually reads. Each of these covers a way the report
// contradicted itself or gave advice that did not apply to the reader, found
// when the privileged setup path was first exercised by hand on two machines.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/setup"
)

// TestTheNoteNeverDeniesAnAnswerThatArrived covers the sharpest of the three
// defects: the note prints directly beneath the line saying whether anything
// answered, so a note claiming nothing could answer, under a line saying
// something did, reads as the report disagreeing with itself.
//
// It exercises the decision rather than a hand-built report, because a report
// assembled in a test would agree with whatever the test put in it and the check
// would pass however the decision was written.
func TestTheNoteNeverDeniesAnAnswerThatArrived(t *testing.T) {
	got := noDaemonNote(true)
	if strings.Contains(got, "nothing could answer") || strings.Contains(got, "nothing here could") {
		t.Errorf("a lookup that was answered is described as unanswerable: %q", got)
	}
	if !strings.Contains(got, "something answered") {
		t.Errorf("the note does not acknowledge the answer that arrived: %q", got)
	}
	if !strings.Contains(got, "not running") {
		t.Errorf("the note no longer says why it was not us: %q", got)
	}
}

// TestTheNoteStillExplainsAnUnansweredLookup is the other half. Removing the
// contradiction must not cost the honest case its explanation, or somebody whose
// lookup genuinely failed loses the one line telling them why.
func TestTheNoteStillExplainsAnUnansweredLookup(t *testing.T) {
	got := noDaemonNote(false)
	if !strings.Contains(got, "nothing here could answer") {
		t.Errorf("an unanswered lookup is no longer explained: %q", got)
	}
	if strings.Contains(got, "something answered") {
		t.Errorf("an unanswered lookup is described as answered: %q", got)
	}
}

// TestBothNotesAreRenderedWhereAPersonReadsThem keeps the wiring covered: the
// decision above is only useful if it reaches the page.
func TestBothNotesAreRenderedWhereAPersonReadsThem(t *testing.T) {
	for _, answered := range []bool{true, false} {
		r := report{
			Suffix:   "internal",
			Resolver: resolverReport{Kind: "systemd-resolved", Supported: true},
			Daemon:   &daemonReport{Running: false},
			Resolution: resolutionCheck{
				Name:     "abc123._probe.internal",
				Answered: answered,
				Note:     noDaemonNote(answered),
			},
		}
		var out bytes.Buffer
		writeReport(&out, r)
		got := out.String()

		if answered && strings.Contains(got, "nothing could answer") {
			t.Errorf("answered=true still renders a denial:\n%s", got)
		}
		if !answered && !strings.Contains(got, "responder is not running") {
			t.Errorf("answered=false loses its explanation:\n%s", got)
		}
	}
}

// TestAdviceUnderSudoDoesNotSendSomeoneToRemakeWhatTheyHave covers advice
// computed against the wrong home. A privileged run sees root's home, so
// anything kept per-user reads as absent even when the person running the
// command owns a copy. Telling them to create one sends them to make a second
// identity, which is how a machine ends up with a key the daemon never uses.
func TestAdviceUnderSudoDoesNotSendSomeoneToRemakeWhatTheyHave(t *testing.T) {
	if _, privileged := setup.RealUser(); privileged {
		t.Skip("this check needs an unprivileged run to compare against")
	}

	r := report{
		Suffix:   "internal",
		Resolver: resolverReport{Kind: "systemd-resolved", Supported: true},
		Daemon:   &daemonReport{Running: false},
		Artifacts: []artifactJSON{
			{Scope: "root", Purpose: "resolver registration", Present: true, Ours: true, Current: true},
			{Scope: "user", Purpose: "this machine's identity", Present: false},
			{Scope: "user", Purpose: "your settings", Present: false},
		},
	}

	// Unprivileged, absent really means absent, and the advice should stand.
	if got := nextStep(r, setup.Resolver{}); !strings.Contains(got, "keygen") {
		t.Errorf("unprivileged, a missing identity should still be the next step, got: %q", got)
	}
}

// TestAdviceNamesWhoseViewItIsWhenRunPrivileged asserts the wording a privileged
// run gets. It is driven directly rather than through the real environment, so
// the check does not depend on being run under sudo.
func TestAdviceNamesWhoseViewItIsWhenRunPrivileged(t *testing.T) {
	advice := privilegedViewAdvice("gumbo")
	if !strings.Contains(advice, "gumbo") {
		t.Errorf("the advice does not name whose files are hidden: %q", advice)
	}
	if !strings.Contains(advice, "without sudo") {
		t.Errorf("the advice does not say how to see them: %q", advice)
	}
	if strings.Contains(advice, "keygen") {
		t.Errorf("the advice still tells a privileged run to create a user file: %q", advice)
	}

	anonymous := privilegedViewAdvice("")
	if strings.Contains(anonymous, " are not visible") && strings.Contains(anonymous, "  ") {
		t.Errorf("with no name available the advice reads awkwardly: %q", anonymous)
	}
	if !strings.Contains(anonymous, "per-user files") {
		t.Errorf("with no name available the advice should still say what is hidden: %q", anonymous)
	}
}
