package daemon

// A liveness probe that fails should say what happened to the session. One
// failure had been reporting an assertion about a dialer instead: the control
// stream is deliberately usable once, so reusing a dead one is refused by
// design, and that refusal is worded for whoever reads this package rather than
// for whoever is running the program. Wrapped in two layers of remote-call
// framing it reached a log as the stated reason someone's session dropped.

import (
	"errors"
	"strings"
	"testing"
)

func TestProbeFailureTextTranslatesTheReusedStream(t *testing.T) {
	// The shape the error really arrives in, framing and all.
	raw := errors.New(`rpc error: code = Unavailable desc = connection error: ` +
		`desc = "transport: Error while dialing: control: dialer may only be used once"`)

	got := probeFailureText(raw)

	if strings.Contains(got, "dialer") {
		t.Errorf("the reported reason still quotes the dialer at whoever reads the log: %q", got)
	}
	if strings.Contains(got, "rpc error") || strings.Contains(got, "desc =") {
		t.Errorf("the reported reason still carries remote-call framing: %q", got)
	}
	if !strings.Contains(got, "session") {
		t.Errorf("the reported reason does not say what happened to the session: %q", got)
	}
}

func TestProbeFailureTextPassesThroughEverythingElse(t *testing.T) {
	// Network failures are already the most specific thing available, so they
	// must survive untouched — translating them would lose detail.
	raw := errors.New("timeout: no recent network activity")
	if got := probeFailureText(raw); got != raw.Error() {
		t.Errorf("a network failure was rewritten: got %q, want %q", got, raw.Error())
	}
	if got := probeFailureText(nil); got != "" {
		t.Errorf("no failure should describe nothing, got %q", got)
	}
}
