package tunnel_test

// Tests for the structured client-disconnect event emitted by the agent when
// a client's control stream closes.
//
// Security invariant under test: the agent log may contain at most the first
// 8 characters of a client's pin (the "pin prefix"). The full 44-character
// pin must never appear in any log output.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// TestClientDisconnectEvent verifies that closing a client's control stream
// causes the agent to emit a structured "client disconnected" log line at INFO
// level. The test also enforces the pin-leakage security property: the full
// 44-character pin must not appear anywhere in the captured log output, but the
// 8-character prefix must.
//
// Pre-change failure mode: before the change, the agent logged
// "control stream closed; tearing down session" with only the "peer" key — no
// "client disconnected" event name and no "session_duration" field. The
// assertions on the message text and on "session_duration" would have failed,
// demonstrating behavioural (not compile-only) coverage.
func TestClientDisconnectEvent(t *testing.T) {
	// NOT parallel — replaces the global slog logger; running sequentially
	// prevents cross-contamination with other tests that also capture logs.

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	// _ avoids the "declared but not used" error; the value is consumed below
	// for the pin-leakage assertion.
	_ = clientPin

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

	// Install a race-safe log capture before the server goroutine starts so
	// every line the agent writes lands in the buffer.
	sb := installSyncLogger(t)

	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	// Connect and open the control stream.
	conn := dialConn(t, ctx, clientTLS, serverAddr)

	client, err := control.Open(ctx, conn, "disconnect-event-test", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}

	// Confirm the session is live.
	if _, err := client.PingRTT(ctx); err != nil {
		t.Fatalf("PingRTT: %v", err)
	}

	// Close the client cleanly. This closes the control stream, which the
	// agent treats as session death and emits the disconnect event.
	client.Close()
	conn.CloseWithError(0, "test done") //nolint:errcheck

	// Poll until the agent goroutine has written the disconnect event (or the
	// 2 s deadline expires). This is faster than a fixed sleep on healthy
	// hardware and only waits the full budget when something is broken.
	if !waitForLog(sb, "client disconnected") {
		t.Errorf("expected \"client disconnected\" in agent log within deadline; got:\n%s", sb.String())
	}

	logOutput := sb.String()

	// --- assertion 1: the named disconnect event exists (already checked above)

	// --- assertion 2: session_duration field is present ----------------------
	if !strings.Contains(logOutput, "session_duration") {
		t.Errorf("expected \"session_duration\" field in agent log; got:\n%s", logOutput)
	}

	// --- assertion 3: pin-leakage guard (security-critical) ------------------
	// The full 44-character client pin must never appear in any log line.
	if strings.Contains(logOutput, clientPin) {
		t.Errorf("SECURITY: full 44-char client pin appeared in agent log output (must never log the full pin):\npin=%s\nlog:\n%s",
			clientPin, logOutput)
	}

	// --- assertion 4: the 8-char pin prefix DOES appear in the log ----------
	// peer.Short() is the established pin-truncation mechanism; it returns
	// exactly the first 8 characters of the pin.
	pinPrefix := clientPin[:8]
	if !strings.Contains(logOutput, pinPrefix) {
		t.Errorf("expected 8-char pin prefix %q to appear in agent log; got:\n%s", pinPrefix, logOutput)
	}
}

// TestClientDisconnectEvent_UncleanDeparture verifies that the disconnect event
// also fires when the client drops the connection abruptly (CloseWithError
// without first closing the control client). This covers the "unclean
// departure" path that reaches serveControl via control stream teardown.
func TestClientDisconnectEvent_UncleanDeparture(t *testing.T) {
	// NOT parallel — shares the global slog logger.

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

	sb := installSyncLogger(t)

	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)

	client, err := control.Open(ctx, conn, "disconnect-unclean-test", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	if _, err := client.PingRTT(ctx); err != nil {
		t.Fatalf("PingRTT: %v", err)
	}

	// Drop the connection abruptly without closing the control client first.
	// The agent's control.Serve call will return when its stream is torn down.
	conn.CloseWithError(0, "abrupt disconnect") //nolint:errcheck

	// Poll until the agent goroutine has written the disconnect event, rather
	// than sleeping for a fixed interval that can be too short on a loaded CI.
	if !waitForLog(sb, "client disconnected") {
		t.Errorf("expected \"client disconnected\" in agent log after unclean departure within deadline; got:\n%s", sb.String())
	}

	logOutput := sb.String()

	// The disconnect event must fire on unclean departure too.
	if !strings.Contains(logOutput, "client disconnected") {
		t.Errorf("expected \"client disconnected\" in agent log after unclean departure; got:\n%s", logOutput)
	}

	// Pin-leakage guard.
	if strings.Contains(logOutput, clientPin) {
		t.Errorf("SECURITY: full 44-char client pin appeared in agent log output:\npin=%s\nlog:\n%s",
			clientPin, logOutput)
	}

	pinPrefix := clientPin[:8]
	if !strings.Contains(logOutput, pinPrefix) {
		t.Errorf("expected 8-char pin prefix %q in agent log after unclean departure; got:\n%s", pinPrefix, logOutput)
	}
}

// TestClientDisconnectEvent_FullPinNotInLog is a focused security test:
// it asserts that a known full 44-character pin never leaks into the log,
// even when multiple sessions connect and disconnect.
func TestClientDisconnectEvent_FullPinNotInLog(t *testing.T) {
	// NOT parallel — global slog logger.

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

	sb := installSyncLogger(t)

	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	// Connect, ping, disconnect twice to accumulate log lines. After each
	// disconnect, poll until the "client disconnected" event appears in the log
	// before starting the next connection — this avoids a fixed sleep and
	// ensures we count exactly one event per iteration.
	for i := range 2 {
		conn := dialConn(t, ctx, clientTLS, serverAddr)
		cl, err := control.Open(ctx, conn, "pin-leak-test", control.OpenOpts{})
		if err != nil {
			t.Fatalf("control.Open: %v", err)
		}
		if _, err := cl.PingRTT(ctx); err != nil {
			t.Fatalf("PingRTT: %v", err)
		}
		cl.Close()
		conn.CloseWithError(0, "done") //nolint:errcheck

		// Wait for the agent to log the disconnect event for this iteration.
		// We poll for (i+1) occurrences so each pass waits for exactly one
		// new event rather than re-triggering on a previous one.
		target := strings.Repeat("client disconnected", 1) // used in count check below
		_ = target
		wantCount := i + 1
		const deadline = 2 * time.Second
		end := time.Now().Add(deadline)
		for time.Now().Before(end) {
			if strings.Count(sb.String(), "client disconnected") >= wantCount {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	logOutput := sb.String()

	// The full 44-char pin is 44 characters and contains only base64 chars.
	// It must not appear anywhere in the log output.
	if strings.Contains(logOutput, clientPin) {
		t.Errorf("SECURITY: full 44-char client pin leaked into log:\npin=%s\nlog:\n%s",
			clientPin, logOutput)
	}

	// The server pin must also not appear (we don't log it, but verify anyway).
	if strings.Contains(logOutput, serverPin) {
		t.Errorf("SECURITY: full 44-char server pin leaked into log:\npin=%s\nlog:\n%s",
			serverPin, logOutput)
	}

	// The disconnect event must have fired at least twice.
	count := strings.Count(logOutput, "client disconnected")
	if count < 2 {
		t.Errorf("expected at least 2 \"client disconnected\" events; found %d\nlog:\n%s", count, logOutput)
	}

	// The pin prefix (8 chars) must appear at least twice (once per session).
	pinPrefix := clientPin[:8]
	prefixCount := strings.Count(logOutput, pinPrefix)
	if prefixCount < 2 {
		t.Errorf("expected 8-char pin prefix %q at least twice; found %d\nlog:\n%s",
			pinPrefix, prefixCount, logOutput)
	}
}

// Confirm the tunnel package exports ServeOpts (used across test files).
var _ = tunnel.ServeOpts{}
