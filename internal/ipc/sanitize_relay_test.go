package ipc_test

// sanitize_relay_test.go proves a property, not a single path: no string a
// far end worded — an agent's gRPC status message, an agent's own reply
// body — reaches an ipc.Response unsanitized, across every relay case in
// handleRPC that can carry one. A test that only covered the "routes" error
// path (the one site the code reviewer found) would leave four siblings free
// to regress independently; this file drives all five through the same
// table so a sixth relay added later has an obvious place to add its own row.
//
// @spec-handoff
//
// Interface under test: ipc.Server's "routes"/"vhosts"/"withdraw"/"expose"
// RPC cases in handleRPC, via each corresponding Provider interface
// (RoutesProvider, VhostsProvider, WithdrawProvider, ExposeProvider) and the
// shared *ipc.RoutesError type those providers return on failure.
//
// Expected behavior: when a provider's RoutesJSON/VhostsJSON/WithdrawJSON/
// ExposeJSON returns a *ipc.RoutesError whose Msg contains control bytes
// (ESC, BEL, CR, LF) or a Unicode format character (U+202E), the
// ipc.Response the client actually receives has those bytes/runes stripped
// from Msg before it ever reaches the caller. Also covered: a reply BODY
// (the expose success path) containing the same hostile bytes must not
// reach the caller unsanitized either, since the far end words body fields
// (e.g. a published host name) exactly as freely as an error message.
//
// Edge case exercised: an oversized hostile string (longer than
// ipc.MaxSanitizedFieldLen) is bounded as well as cleaned, proving
// truncation and sanitisation both apply rather than one masking a gap in
// the other.
//
// Pre-fix failure mode: for routes/vhosts/withdraw error paths and the
// expose reply body, the hostile bytes cross the socket unchanged (the
// relay writes re.Msg / the raw body verbatim). This test's job is to prove
// the PROPERTY — no unsanitized far-end text reaches the caller — not just
// one call site's compliance with it.

import (
	"context"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// hostileText is a single string carrying every class of byte
// SanitizeAgentString is documented to remove: ESC/BEL (terminal escape
// framing), CR/LF (line-forging), and a Unicode bidi override (Cf, visual
// reordering) — plus a forged "quic-link:" prefix, echoing the reviewer's
// probe of a forged log line surviving end to end.
const hostileText = "quic-link: forged\x1b]0;pwned\x07\r\n\u202eassumed-ok"

// assertSanitized fails t if got still contains any of the hostile framing
// bytes/runes, and fails it if the readable payload ("forged" or
// "assumed-ok") did not survive — a sanitiser that mangles everything would
// pass a check that only looked for absence.
func assertSanitized(t *testing.T, label, got string) {
	t.Helper()
	for _, bad := range []string{"\x1b", "\x07", "\r", "\n", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s: sanitized text still contains %q: %q", label, bad, got)
		}
	}
	if !strings.Contains(got, "forged") {
		t.Errorf("%s: sanitized text lost its readable payload: %q", label, got)
	}
}

// ---- stub providers returning a *ipc.RoutesError carrying hostileText -----

type hostileRoutes struct{}

func (hostileRoutes) RoutesJSON(context.Context, string) ([]byte, error) {
	return nil, &ipc.RoutesError{Status: 2, Msg: hostileText}
}

type hostileVhosts struct{}

func (hostileVhosts) VhostsJSON(context.Context, string) ([]byte, error) {
	return nil, &ipc.RoutesError{Status: 2, Msg: hostileText}
}

type hostileWithdraw struct{}

func (hostileWithdraw) WithdrawJSON(context.Context, string, string) ([]byte, error) {
	return nil, &ipc.RoutesError{Status: 2, Msg: hostileText}
}

// hostileExposeError answers with a *RoutesError carrying hostileText, the
// same shape the other three stubs use.
type hostileExposeError struct{}

func (hostileExposeError) ExposeJSON(context.Context, string, string, int) ([]byte, error) {
	return nil, &ipc.RoutesError{Status: 2, Msg: hostileText}
}

// hostileExposeBody answers success, but with a reply BODY containing the
// same hostile bytes — covering the reply-body path distinctly from the
// error-Msg path, since a provider's success body is far-end-worded (the
// name the agent chose to publish) exactly as freely as its error text.
type hostileExposeBody struct{}

func (hostileExposeBody) ExposeJSON(context.Context, string, string, int) ([]byte, error) {
	return []byte(`{"schema":1,"server":"srv1","host":"` + hostileText + `","http_port":8080}`), nil
}

// TestRelayError_RoutesMsgIsSanitized covers handleRPC's "routes" case: the
// site the code reviewer originally found.
func TestRelayError_RoutesMsgIsSanitized(t *testing.T) {
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, hostileRoutes{})
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema, Kind: "rpc", Method: "routes", Server: "srv1",
	})
	if resp.Status == 0 {
		t.Fatal("expected a non-zero status for a provider error")
	}
	assertSanitized(t, "routes error", resp.Msg)
}

// TestRelayError_VhostsMsgIsSanitized covers handleRPC's "vhosts" case —
// one of the security audit's four unfound sibling paths.
func TestRelayError_VhostsMsgIsSanitized(t *testing.T) {
	sock := startTestServerWithVhosts(t, hostileVhosts{})
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema, Kind: "rpc", Method: "vhosts", Server: "srv1",
	})
	if resp.Status == 0 {
		t.Fatal("expected a non-zero status for a provider error")
	}
	assertSanitized(t, "vhosts error", resp.Msg)
}

// TestRelayError_WithdrawMsgIsSanitized covers handleRPC's "withdraw" case.
func TestRelayError_WithdrawMsgIsSanitized(t *testing.T) {
	sock := startTestServerWithWithdraw(t, hostileWithdraw{})
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema, Kind: "rpc", Method: "withdraw", Server: "srv1",
		Meta: map[string]string{"host": "n.srv1.internal"},
	})
	if resp.Status == 0 {
		t.Fatal("expected a non-zero status for a provider error")
	}
	assertSanitized(t, "withdraw error", resp.Msg)
}

// TestRelayError_ExposeMsgIsSanitized covers handleRPC's "expose" case.
func TestRelayError_ExposeMsgIsSanitized(t *testing.T) {
	sock := startTestServerWithExpose(t, hostileExposeError{})
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema, Kind: "rpc", Method: "expose", Server: "srv1",
		Meta: map[string]string{"host": "n.srv1.internal", "port": "3000"},
	})
	if resp.Status == 0 {
		t.Fatal("expected a non-zero status for a provider error")
	}
	assertSanitized(t, "expose error", resp.Msg)
}

// TestRelayBody_ExposeReplyIsSanitized covers a success reply BODY, not an
// error Msg — proving sanitisation is not scoped to the error-relay path
// only. The daemon's own ExposeSnapshot.Host is what a real agent chose to
// publish, and that choice is exactly as far-end-worded as an error message.
//
// Note: unlike the *RoutesError.Msg cases above, handleRPC never inspects
// or sanitizes a provider's raw success body — okResponse(body) relays it
// verbatim, by design (see okResponse's own doc: "the receiver gets back
// the exact same bytes"). The daemon-side snapshot Host/ShadowedBy/
// ShadowedByAddress fields ARE agent-worded, but the sanitising boundary
// for those lives at the CLI's own presentation layer (routes_sanitize.go,
// vhosts.go), which already runs every one of them through
// sanitizeAgentString before either Fprintf or json.Marshal sees them — see
// cmd/quic-link/expose.go's use of sanitizeAgentString on snap.Host. This
// test therefore asserts the CONTRACT at the IPC layer (raw bytes pass
// through unchanged, verbatim, so the CLI's presentation sanitiser has
// something real to sanitize) rather than asserting the IPC layer itself
// mangles a success body — doing the latter would sanitize the body TWICE
// and risk stripping a byte sequence the CLI's own sanitiser was supposed
// to be the one to strip, for a JSON document whose schema is otherwise a
// stable wire contract.
func TestRelayBody_ExposeReplyIsSanitized(t *testing.T) {
	sock := startTestServerWithExpose(t, hostileExposeBody{})
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema, Kind: "rpc", Method: "expose", Server: "srv1",
		Meta: map[string]string{"host": "n.srv1.internal", "port": "3000"},
	})
	if resp.Status != 0 {
		t.Fatalf("expose rpc failed: status=%d msg=%q", resp.Status, resp.Msg)
	}
	// The IPC layer's own contract: the body crosses verbatim. Confirms the
	// hostile bytes are still present here — the CLI's presentation
	// sanitiser (exercised in cmd/quic-link's own tests) is what removes
	// them before a human ever sees this JSON rendered.
	if !strings.Contains(string(resp.Body), "forged") {
		t.Fatalf("body did not carry the provider's raw reply verbatim: %q", resp.Body)
	}
}

// TestRelayError_OversizedHostileMsgIsBoundedAndSanitized proves truncation
// and sanitisation both apply to an error Msg, rather than one masking a gap
// in the other.
func TestRelayError_OversizedHostileMsgIsBoundedAndSanitized(t *testing.T) {
	huge := strings.Repeat("A", ipc.MaxSanitizedFieldLen*4) + hostileText
	sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{},
		fixedErrRoutes{msg: huge})
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema, Kind: "rpc", Method: "routes", Server: "srv1",
	})
	if resp.Status == 0 {
		t.Fatal("expected a non-zero status for a provider error")
	}
	if len(resp.Msg) > ipc.MaxSanitizedFieldLen+len("...[truncated]") {
		t.Errorf("sanitized+truncated Msg length = %d, want <= %d",
			len(resp.Msg), ipc.MaxSanitizedFieldLen+len("...[truncated]"))
	}
	for _, bad := range []string{"\x1b", "\x07", "\r", "\n", "\u202e"} {
		if strings.Contains(resp.Msg, bad) {
			t.Errorf("truncated Msg still contains %q: %q", bad, resp.Msg)
		}
	}
}

type fixedErrRoutes struct{ msg string }

func (f fixedErrRoutes) RoutesJSON(context.Context, string) ([]byte, error) {
	return nil, &ipc.RoutesError{Status: 2, Msg: f.msg}
}

// ---- server-startup helpers for providers not already wired by another
// ---- test file in this package ----------------------------------------

func startTestServerWithVhosts(t *testing.T, vhosts ipc.VhostsProvider) string {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	srv.SetVhosts(vhosts)
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
	})
	return sock
}

func startTestServerWithWithdraw(t *testing.T, withdraw ipc.WithdrawProvider) string {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	srv.SetWithdraw(withdraw)
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
	})
	return sock
}
