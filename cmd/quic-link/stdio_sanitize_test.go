package main

// stdio_sanitize_test.go — regression test for the direct-dial refusal path.
//
// Defect (r4-sho-remediation-confirm.md finding #1): stdioRun's direct-QUIC
// path (no daemon) printed the far end's proto.Response.Msg verbatim to
// os.Stderr on a non-OK attach response. That Msg is worded entirely by
// whoever answers the handshake — status.Convert-style trust does not apply
// here; a stream response is even less constrained than a gRPC status
// message. This path bypasses both the daemon and the IPC socket, so neither
// ipc.SanitizeAgentString (internal/ipc/server.go:759) nor
// routesErrorResponse (internal/ipc/server.go) ever sees it — it is a
// distinct channel from every other far-end-text path this plan sanitized.
//
// This test drives the real path end to end against a hostile agent that
// speaks the wire protocol directly (not tunnel.Serve/tunnel.OpenControl —
// deliberately below both, to plant an arbitrary Msg no legitimate agent
// implementation in this tree would ever construct) and asserts the
// PROPERTY: whatever the far end sends as its refusal Msg, once it reaches
// stdout/stderr, contains none of the hostile framing bytes/runes
// SanitizeAgentString exists to remove. A test that hardcoded one specific
// hostile string and one specific clean expectation would only pin that one
// string; this drives every byte class the shared sanitizer documents.

import (
	"context"
	"crypto/ed25519"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// stdioSanitizeHostileMsg carries one instance of every class
// ipc.SanitizeAgentString documents removing (ESC/BEL terminal-escape
// framing, CR/LF line-forging, a Unicode bidi override) plus a forged
// "quic-link:" log-line prefix, echoing the reviewer's own probe.
const stdioSanitizeHostileMsg = "PROBE\x1b]0;pwned\x07\r\nquic-link: forged-ok-line\u202e"

// TestStdioRun_DirectDialRefusal_SanitizesAgentMsg drives stdioRun's
// direct-QUIC fallback against a hostile agent that authenticates correctly
// (a real, pinned handshake — this is not an unauthenticated-peer bug) but
// refuses the data stream with a Msg containing the hostile payload above.
// Asserts the property: neither the returned error's message (which stdio.go
// prints to stderr and also carries into statusError) nor anything written to
// stdout contains any of the hostile bytes/runes, while the readable payload
// ("PROBE", "forged-ok-line") survives — proving sanitization ran rather than
// mangled everything.
func TestStdioRun_DirectDialRefusal_SanitizesAgentMsg(t *testing.T) {
	// No t.Parallel(): captureAll swaps the process-global os.Stdout/
	// os.Stderr for the duration of fn, which is incompatible with running
	// concurrently with any other test doing the same (as ping_sanitize_test.go's
	// sibling test does).
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := stdioSanitizeGenIdentity(t)
	clientKey, clientPin := stdioSanitizeGenIdentity(t)

	serverTLS, err := identity.AgentListenTLS(serverKey, []string{clientPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}
	// stdioRun builds its own client TLS config via clientTLSFromFlags from
	// the key file and serverPin below; nothing here needs a second one.

	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("server UDP: %v", err)
	}
	t.Cleanup(func() { serverUDP.Close() })
	serverTr, err := transport.NewQUICTransport(serverUDP, serverTLS, nil)
	if err != nil {
		t.Fatalf("server transport: %v", err)
	}
	t.Cleanup(func() { serverTr.Close() })
	ln, err := serverTr.Listen()
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		stdioSanitizeRunHostileAgent(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-agentDone
	})

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "client_key.pem")
	if err := identity.WriteKey(keyFile, clientKey); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	stdout, stderr, runErr := captureAll(t, func() error {
		return stdioRun(ctx, ln.Addr().String(), "ssh", keyFile, serverPin)
	})

	if runErr == nil {
		t.Fatal("stdioRun: expected an error for a non-OK attach response, got nil")
	}

	// STDOUT DISCIPLINE (stdio.go's own contract): only tunnelled bytes may
	// ever reach stdout. A refusal never reaches the splice, so stdout must
	// be completely empty — not merely "sanitized," but untouched.
	if stdout != "" {
		t.Errorf("stdout must stay clean on a refusal; got %q", stdout)
	}

	assertNoHostileBytes(t, "stderr", strings.TrimSuffix(stderr, "\n"))
	assertNoHostileBytes(t, "returned error", runErr.Error())

	// The readable payload must survive sanitization — a sanitizer that
	// mangled everything would pass a check that only looked for absence.
	if !strings.Contains(stderr, "PROBE") {
		t.Errorf("stderr lost the agent's readable payload: %q", stderr)
	}
	if !strings.Contains(stderr, "forged-ok-line") {
		t.Errorf("stderr lost the agent's readable payload: %q", stderr)
	}
}

// assertNoHostileBytes fails t if got contains any byte/rune
// ipc.SanitizeAgentString documents removing.
func assertNoHostileBytes(t *testing.T, label, got string) {
	t.Helper()
	for _, bad := range []string{"\x1b", "\x07", "\r", "\n", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s: still contains hostile byte/rune %q: %q", label, bad, got)
		}
	}
}

func stdioSanitizeGenIdentity(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		t.Fatalf("pin for key: %v", err)
	}
	return key, pin
}

// stdioSanitizeRunHostileAgent speaks the wire protocol directly rather than
// using tunnel.Serve — deliberately below it, since a legitimate agent
// implementation in this tree's router never constructs an arbitrary Msg of
// the shape this test needs. It runs a real control.Serve on the control
// stream (so stdioRun's control-stream open genuinely succeeds, exactly as
// against a real agent) and answers the data stream with a non-OK status
// carrying stdioSanitizeHostileMsg, exactly as router.ErrUnauthorized or an
// unknown-target refusal would carry whatever text this build's own router
// chose, but with the choice inverted: here the far end chooses.
func stdioSanitizeRunHostileAgent(ctx context.Context, ln transport.Listener) {
	conn, err := ln.Accept(ctx)
	if err != nil {
		return
	}
	defer conn.CloseWithError(0, "hostile agent done") //nolint:errcheck

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go stdioSanitizeServeOneStream(ctx, stream)
	}
}

func stdioSanitizeServeOneStream(ctx context.Context, stream transport.Stream) {
	h, err := proto.ReadHeader(stream)
	if err != nil {
		return
	}
	switch h.Kind {
	case proto.KindControl:
		// A real control.Serve, not a hand-rolled OK response: control.Open
		// (which tunnel.OpenControl calls) issues an establishing Ping RPC
		// over this stream immediately after the header/response handshake,
		// so stdioRun's control-stream open only succeeds if something
		// actually answers gRPC on the other end.
		if err := proto.WriteResponse(stream, proto.Response{Status: proto.StatusOK}); err != nil {
			return
		}
		_ = control.Serve(ctx, stream, control.PeerIdentity{}, control.AllowAll{})
	default:
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnauthorized,
			Msg:    stdioSanitizeHostileMsg,
		})
		_ = stream.Close()
	}
}
