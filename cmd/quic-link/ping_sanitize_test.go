package main

// ping_sanitize_test.go — regression test for ping's control-RPC failure
// printer.
//
// Defect: pingRun printed res.RPCErr with a bare %v Printf. res.RPCErr can
// carry proto.Response.Msg verbatim — control.Open (internal/control/open.go)
// returns the agent's own wording on a non-OK control-stream response, worded
// entirely by whoever answered this probe's handshake. This is a distinct
// channel from every gRPC-status-message path the plan's earlier rounds
// sanitized: it is the same family as stdio's direct-dial refusal (both are
// proto.Response.Msg on the raw QUIC stream, not something that ever crosses
// the daemon's IPC socket or its SanitizeAgentString boundary).
//
// This test drives pingRun end to end against a hostile agent that
// authenticates correctly but answers the control-stream open with a non-OK
// status carrying hostile bytes, and asserts the property: stdout never
// contains the hostile framing bytes/runes, while the readable payload
// survives.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// pingSanitizeHostileMsg mirrors stdio_sanitize_test.go's
// stdioSanitizeHostileMsg — one instance of every class
// ipc.SanitizeAgentString documents removing, plus a forged log-line prefix.
const pingSanitizeHostileMsg = "PROBE\x1b]0;pwned\x07\r\nquic-link: forged-ok-line\u202e"

// TestPingRun_ControlOpenRefusal_SanitizesAgentMsg drives pingRun against an
// agent that completes the QUIC/TLS pin handshake normally but refuses the
// control-stream open with a hostile Msg. res.RPCErr carries that Msg, and
// pingRun's own renderer must sanitize it before Printf ever sees it.
func TestPingRun_ControlOpenRefusal_SanitizesAgentMsg(t *testing.T) {
	// No t.Parallel(): captureAll swaps the process-global os.Stdout/
	// os.Stderr for the duration of fn, which is incompatible with running
	// concurrently with any other test doing the same (as
	// stdio_sanitize_test.go's sibling test does).
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	agentKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	agentPin, err := identity.PinForKey(agentKey)
	if err != nil {
		t.Fatalf("agent pin: %v", err)
	}
	clientKey, err := identity.Generate()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientPin, err := identity.PinForKey(clientKey)
	if err != nil {
		t.Fatalf("client pin: %v", err)
	}

	agentTLS, err := identity.AgentListenTLS(agentKey, []string{clientPin})
	if err != nil {
		t.Fatalf("AgentListenTLS: %v", err)
	}

	agentUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("agent UDP: %v", err)
	}
	t.Cleanup(func() { agentUDP.Close() })
	agentTr, err := transport.NewQUICTransport(agentUDP, agentTLS, nil)
	if err != nil {
		t.Fatalf("agent transport: %v", err)
	}
	t.Cleanup(func() { agentTr.Close() })
	ln, err := agentTr.Listen()
	if err != nil {
		t.Fatalf("agent listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		pingSanitizeRunHostileAgent(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-agentDone
	})

	dir := t.TempDir()
	keyFile := dir + "/client_key.pem"
	if err := identity.WriteKey(keyFile, clientKey); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	stdout, _, runErr := captureAll(t, func() error {
		return pingRun(ctx, ln.Addr().String(), 1, keyFile, agentPin)
	})

	// pingRun reports a per-probe control_rpc failure but does not fail the
	// whole run for it (probe.Ping's own doc: "the transport measurements
	// are always returned; a control-stream failure is non-fatal"). What
	// matters here is what reached stdout, not the return value.
	_ = runErr

	// Isolate the control_rpc line: stdout has several legitimate lines
	// (the probe summary, statistics) each properly newline-terminated, so
	// checking the whole capture for "\n" would flag structure that has
	// nothing to do with the agent's message. What must contain none of the
	// hostile bytes is the rendered agent text itself.
	line := pingSanitizeExtractControlRPCLine(t, stdout)
	assertNoHostileBytes(t, "control_rpc line", line)
	if !strings.Contains(line, "PROBE") {
		t.Errorf("control_rpc line lost the agent's readable payload: %q", line)
	}
	if !strings.Contains(line, "forged-ok-line") {
		t.Errorf("control_rpc line lost the agent's readable payload: %q", line)
	}
}

// pingSanitizeExtractControlRPCLine returns the single line containing
// "control_rpc: FAILED", failing t if none or more than one is found.
func pingSanitizeExtractControlRPCLine(t *testing.T, stdout string) string {
	t.Helper()
	var found []string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.Contains(l, "control_rpc: FAILED") {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one control_rpc failure line, found %d: stdout=%q", len(found), stdout)
	}
	return found[0]
}

// pingSanitizeRunHostileAgent completes the QUIC/TLS handshake normally (a
// real, pinned session) then refuses the control-stream open with a non-OK
// status carrying pingSanitizeHostileMsg — the direct-QUIC-protocol
// equivalent of what a compromised-but-correctly-pinned agent could send.
func pingSanitizeRunHostileAgent(ctx context.Context, ln transport.Listener) {
	conn, err := ln.Accept(ctx)
	if err != nil {
		return
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	if _, err := proto.ReadHeader(stream); err != nil {
		return
	}
	_ = proto.WriteResponse(stream, proto.Response{
		Status: proto.StatusUnsupportedVersion,
		Msg:    pingSanitizeHostileMsg,
	})
	// Give the client time to read the response frame before this
	// connection goes away — closing immediately risks the client's read
	// racing the close and observing a transport error instead of the
	// response this test needs it to see.
	<-conn.Context().Done()
}
