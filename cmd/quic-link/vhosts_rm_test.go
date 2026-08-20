package main

// What a person and a script see when a withdrawal leaves the name answered.
//
// These drive the real verb through a real local socket, because the two
// interesting properties live in the rendering rather than in any function that
// could be called directly: whether the extra line says where the name is served
// now, and whether the machine-readable document omits the pair entirely when
// nothing took it over.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// stubWithdrawProvider is an ipc.WithdrawProvider returning a fixed document.
type stubWithdrawProvider struct {
	body []byte
	err  error
}

func (s *stubWithdrawProvider) WithdrawJSON(_ context.Context, _, _ string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.body, nil
}

// startWithdrawServerAtPath starts a real ipc.Server with a withdrawal provider
// wired, at the socket path the verb itself will resolve.
func startWithdrawServerAtPath(t *testing.T, w ipc.WithdrawProvider) {
	t.Helper()
	sock, err := daemonSocketPath(nil)
	if err != nil {
		t.Fatalf("daemonSocketPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	srv := ipc.NewServer(sock, &stubStatusProvider{data: []byte(testStatusJSON)}, nil)
	srv.SetWithdraw(w)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		os.Remove(sock)
	})
}

// runVhostsRmForTest executes the real verb against a daemon answering with body
// and returns what it wrote to stdout.
func runVhostsRmForTest(t *testing.T, body string, extraArgs ...string) string {
	t.Helper()
	unsetQLEnvForTest(t)
	withDaemonSocketEnv(t)
	pin := mustTestPin(t)
	path := testConfig(t, pin)

	startWithdrawServerAtPath(t, &stubWithdrawProvider{body: []byte(body)})

	root := newRootCmd()
	var stdout strings.Builder
	root.SetOut(&stdout)
	args := append([]string{"--config", path, "vhosts", "rm", "grafana.server1.internal"}, extraArgs...)
	root.SetArgs(args)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("vhosts rm: %v", err)
	}
	return stdout.String()
}

// TestVhostsRm_HumanSaysWhereTheNameIsAnsweredNow is the point of the whole
// change. "still answered by *.server1.internal" tells a reader their withdrawal
// did not stop the name resolving and then declines to say what it now reaches,
// which is the question that immediately follows and usually has a different
// answer than the entry just removed.
func TestVhostsRm_HumanSaysWhereTheNameIsAnsweredNow(t *testing.T) {
	got := runVhostsRmForTest(t, `{"schema":1,"server":"server1",`+
		`"host":"grafana.server1.internal","shadowed_by":"*.server1.internal",`+
		`"shadowed_by_address":"tcp://127.0.0.1:3000"}`)

	if !strings.Contains(got, "withdrawn: grafana.server1.internal") {
		t.Errorf("the success line is missing: %q", got)
	}
	if !strings.Contains(got, "*.server1.internal") {
		t.Errorf("the pattern that took over is not named: %q", got)
	}
	if !strings.Contains(got, "tcp://127.0.0.1:3000") {
		t.Errorf("the output says the name is still answered but not where; the address is "+
			"the half a reader can act on: %q", got)
	}
}

// TestVhostsRm_NothingTakesOverAndTheDocumentOmitsBothFields asserts on the raw
// bytes rather than a decoded struct, because a decoded field reads as "" whether
// the key was absent or present-and-empty — which is exactly the distinction the
// contract makes. A reader is promised absence means "nothing took over".
func TestVhostsRm_NothingTakesOverAndTheDocumentOmitsBothFields(t *testing.T) {
	got := runVhostsRmForTest(t,
		`{"schema":1,"server":"server1","host":"grafana.server1.internal"}`, "--json")

	if strings.Contains(got, "shadowed_by") {
		t.Errorf("nothing took the name over, but the document carries a shadow key: %q", got)
	}

	// Still a well-formed document with the fields that are always present, so
	// the absence above is an omission and not a failure to produce anything.
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v (%q)", err, got)
	}
	if doc["host"] != "grafana.server1.internal" {
		t.Errorf("the document does not name what was withdrawn: %q", got)
	}
}

// TestVhostsRm_JSONCarriesTheAddressWhenAPatternTookOver is the other half of the
// test above: the key has to appear when there is something to report, or the
// omission rule would be satisfied by never emitting it at all.
func TestVhostsRm_JSONCarriesTheAddressWhenAPatternTookOver(t *testing.T) {
	got := runVhostsRmForTest(t, `{"schema":1,"server":"server1",`+
		`"host":"grafana.server1.internal","shadowed_by":"*.server1.internal",`+
		`"shadowed_by_address":"tcp://127.0.0.1:3000"}`, "--json")

	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v (%q)", err, got)
	}
	if doc["shadowed_by_address"] != "tcp://127.0.0.1:3000" {
		t.Errorf("the document does not carry where the name is answered now: %q", got)
	}
}

// TestVhostsRm_TheShadowAddressIsSanitisedInBothModes closes the gap a new
// agent-supplied field opens. The address is chosen by the far end, and pinning
// proves which key answered rather than what its holder put in a field, so this
// string reaches a terminal and a script with exactly the same standing as the
// host and the pattern beside it.
//
// The hostile value carries the framing bytes an escape sequence needs, a line
// break that could forge a second line of output, and a bidi override whose only
// purpose is to make honest text render in a misleading order.
func TestVhostsRm_TheShadowAddressIsSanitisedInBothModes(t *testing.T) {
	const hostile = "tcp://127.0.0.1:3000\x1b]0;pwned\x07\r\nwithdrawn: something.else\u202e"

	body := `{"schema":1,"server":"server1","host":"grafana.server1.internal",` +
		`"shadowed_by":"*.server1.internal","shadowed_by_address":` +
		mustJSONString(t, hostile) + `}`

	for _, mode := range []struct {
		name string
		args []string
	}{
		{"human", nil},
		{"json", []string{"--json"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			got := runVhostsRmForTest(t, body, mode.args...)

			if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
				t.Errorf("stdout carries the framing bytes of an escape sequence: %q", got)
			}
			if strings.ContainsRune(got, '\u202e') {
				t.Errorf("stdout carries a bidi override, so the agent can choose how honest "+
					"text renders: %q", got)
			}
			if strings.ContainsRune(got, '\r') {
				t.Errorf("stdout carries a carriage return: %q", got)
			}
			// One trailing newline, whatever the agent sent. A line break that
			// survived would let the far end forge a whole line of output.
			if n := strings.Count(strings.TrimRight(got, "\n"), "\n"); n > 1 {
				t.Errorf("the agent's address changed the line count to %d line breaks: %q", n, got)
			}
			// The printable payload still arrives, so the sanitiser is stripping
			// framing rather than discarding the field.
			if !strings.Contains(got, "tcp://127.0.0.1:3000") {
				t.Errorf("the address was lost entirely rather than made inert: %q", got)
			}
		})
	}
}
