package tunnel_test

// Key-age hygiene tests — three concerns:
//
//  1. control.Open stamps key_created in the outbound control header when a
//     non-empty creation time is supplied (and omits the key when empty).
//  2. The agent logs a rotation advisory when an authenticated client
//     self-reports an over-age key via the control-stream header — but the
//     session still comes up (advisory-only).
//  3. A client that sends no key_created field at all also connects without
//     error.

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- thread-safe slog capture -----------------------------------------------

// syncBuffer is a bytes.Buffer protected by a mutex so server goroutines and
// the test goroutine can safely share it as the slog output target.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// installSyncLogger replaces the default slog logger with one that writes to
// a syncBuffer for the duration of the test. Returns the buffer and a restore
// function registered with t.Cleanup.
func installSyncLogger(t *testing.T) *syncBuffer {
	t.Helper()
	sb := &syncBuffer{}
	h := slog.NewTextHandler(sb, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	return sb
}

// warnLines returns lines from sb that contain the substring "WARN".
func warnLines(sb *syncBuffer) []string {
	var out []string
	for _, line := range strings.Split(sb.String(), "\n") {
		if strings.Contains(line, "WARN") {
			out = append(out, line)
		}
	}
	return out
}

// ---- wire-level unit test: proto.Header carries key_created iff non-empty ---

// TestControlHeaderKeyCreatedField verifies the presence/absence of
// key_created in the serialised control-stream header, mirroring the logic
// inside control.Open.
func TestControlHeaderKeyCreatedField(t *testing.T) {
	cases := []struct {
		name        string
		keyCreated  string
		expectField bool
	}{
		{"non-empty stamps field", "2020-06-01T12:00:00Z", true},
		{"empty omits field", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]string{"proto": "1", "version": "test"}
			if tc.keyCreated != "" {
				meta["key_created"] = tc.keyCreated
			}
			h := proto.Header{Kind: proto.KindControl, Meta: meta}

			var buf bytes.Buffer
			if err := proto.WriteHeader(&buf, h); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}
			got, err := proto.ReadHeader(&buf)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}

			_, present := got.Meta["key_created"]
			if present != tc.expectField {
				t.Errorf("key_created present=%v, want %v (meta=%v)", present, tc.expectField, got.Meta)
			}
			if tc.expectField && got.Meta["key_created"] != tc.keyCreated {
				t.Errorf("key_created=%q, want %q", got.Meta["key_created"], tc.keyCreated)
			}
		})
	}
}

// ---- control.Open integration: key_created field stamped on live session ----

// TestControlOpenStampsKeyCreated verifies that a non-empty KeyCreated passed
// to control.Open results in a successful session — the agent must accept the
// header without error.
func TestControlOpenStampsKeyCreated(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck

	keyCreated := "2020-01-01T00:00:00Z"
	client, err := control.Open(ctx, conn, "test", control.OpenOpts{KeyCreated: keyCreated})
	if err != nil {
		t.Fatalf("control.Open with KeyCreated: %v", err)
	}
	defer client.Close() //nolint:errcheck

	if _, err := client.PingRTT(ctx); err != nil {
		t.Fatalf("PingRTT after keyed open: %v", err)
	}
}

// TestControlOpenOmitsKeyCreatedWhenEmpty verifies that an empty KeyCreated
// does not break the control handshake.
func TestControlOpenOmitsKeyCreatedWhenEmpty(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck

	client, err := control.Open(ctx, conn, "test", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open with empty KeyCreated: %v", err)
	}
	defer client.Close() //nolint:errcheck

	if _, err := client.PingRTT(ctx); err != nil {
		t.Fatalf("PingRTT: %v", err)
	}
}

// ---- C. Agent advisory for over-age peer key --------------------------------

// TestAgentAdvisory is a sequential test (no t.Parallel) that runs both
// advisory scenarios in order so each scenario's log capture is isolated from
// the other's server goroutine.  The two sub-tests share a parent test's
// serial execution to avoid global-logger cross-contamination between parallel
// tests.
func TestAgentAdvisory(t *testing.T) {
	// NOT parallel — these sub-tests redirect the global slog logger; running
	// them sequentially prevents one sub-test's server goroutine from writing
	// into another sub-test's capture buffer.

	// Sub-test 1: over-age key_created must produce a WARN advisory while the
	// session still succeeds.
	t.Run("over-age peer key still connects and logs advisory", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		serverKey, serverPin := mustGenIdentity(t)
		clientKey, clientPin := mustGenIdentity(t)
		serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
		clientTLS := mustClientTLS(t, clientKey, serverPin)

		rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

		// Install a race-safe slog capture before starting the server goroutine.
		sb := installSyncLogger(t)

		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatalf("server UDP: %v", err)
		}
		t.Cleanup(func() { udpConn.Close() })
		tr, err := transport.NewQUICTransport(udpConn, serverTLS, nil)
		if err != nil {
			t.Fatalf("server transport: %v", err)
		}
		t.Cleanup(func() { tr.Close() })
		ln, err := tr.Listen()
		if err != nil {
			t.Fatalf("server listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		go tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{WarnKeyAgeDays: 90}) //nolint:errcheck

		// Client presents a key created 200 days ago (over the 90-day threshold).
		pastTime := time.Now().UTC().Add(-200 * 24 * time.Hour).Format(time.RFC3339)

		conn := dialConn(t, ctx, clientTLS, ln.Addr().String())
		t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck

		// The session MUST succeed — key_created is advisory, not a gate.
		client, err := control.Open(ctx, conn, "test-advisory", control.OpenOpts{KeyCreated: pastTime})
		if err != nil {
			t.Fatalf("control.Open with over-age key_created: expected success (advisory-only), got %v", err)
		}
		defer client.Close() //nolint:errcheck

		// Confirm the control stream is live.
		if _, err := client.PingRTT(ctx); err != nil {
			t.Fatalf("PingRTT after over-age key_created: %v", err)
		}

		// Give the server goroutine time to write the advisory log before
		// we inspect the buffer.
		time.Sleep(300 * time.Millisecond)

		warns := warnLines(sb)
		found := false
		for _, w := range warns {
			if strings.Contains(w, "age") || strings.Contains(w, "advisory") ||
				strings.Contains(w, "over") || strings.Contains(w, "rotation") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected agent to log an over-age advisory; WARN lines: %v", warns)
		}
	})

	// Sub-test 2: absent key_created must produce no age advisory.
	t.Run("no key_created connects without advisory", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		serverKey, serverPin := mustGenIdentity(t)
		clientKey, clientPin := mustGenIdentity(t)
		serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
		clientTLS := mustClientTLS(t, clientKey, serverPin)

		rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)

		sb := installSyncLogger(t)

		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatalf("server UDP: %v", err)
		}
		t.Cleanup(func() { udpConn.Close() })
		tr, err := transport.NewQUICTransport(udpConn, serverTLS, nil)
		if err != nil {
			t.Fatalf("server transport: %v", err)
		}
		t.Cleanup(func() { tr.Close() })
		ln, err := tr.Listen()
		if err != nil {
			t.Fatalf("server listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		go tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{WarnKeyAgeDays: 90}) //nolint:errcheck

		conn := dialConn(t, ctx, clientTLS, ln.Addr().String())
		t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck

		// No key_created — the agent must not log an age advisory.
		client, err := control.Open(ctx, conn, "test-no-keyage", control.OpenOpts{})
		if err != nil {
			t.Fatalf("control.Open with no key_created: %v", err)
		}
		defer client.Close() //nolint:errcheck

		if _, err := client.PingRTT(ctx); err != nil {
			t.Fatalf("PingRTT: %v", err)
		}

		time.Sleep(300 * time.Millisecond)

		for _, line := range strings.Split(sb.String(), "\n") {
			if strings.Contains(line, "WARN") &&
				(strings.Contains(line, "age") || strings.Contains(line, "advisory") || strings.Contains(line, "over")) {
				t.Errorf("unexpected age advisory logged when no key_created sent: %s", line)
			}
		}
	})
}
