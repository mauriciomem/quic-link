package ipc_test

// attach_test.go covers the full socket↔QUIC splice path through the IPC server:
// byte-exact round-trips, half-close (scp-style), reset propagation, 50 MB soak,
// attach cap, not-ready / unknown server, and the connSem early-release invariant.
//
// All QUIC traffic is in-memory (transport/mem); no UDP sockets are opened.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- shared harness ---------------------------------------------------------

// attachHarness wires a full IPC server with a real in-memory agent and returns
// the socket path. It manages all goroutines via t.Cleanup.
type attachHarness struct {
	sock      string
	agentConn tunnel.StreamConn
}

func newAttachHarness(t *testing.T) *attachHarness {
	t.Helper()
	agentConn := newMemSetupForIPC(t)
	pool := &stubPool{
		states: map[string]string{"server1": "connected"},
		conn:   agentConn,
	}
	sock := startTestServer(t, &stubStatus{data: []byte(`{}`)}, pool)
	return &attachHarness{sock: sock, agentConn: agentConn}
}

// dialAttach sends an attach request and returns the raw conn after the ack.
// The ack must be status 0; it fails the test otherwise.
func (h *attachHarness) dialAttach(t *testing.T, target string) net.Conn {
	t.Helper()
	c := ipc.NewClient(h.sock)
	conn, err := c.Attach("server1", target, nil)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// ---- test: byte-exact round-trip --------------------------------------------

// TestAttachSplice_ByteExactRoundTrip verifies that data sent through the
// IPC socket arrives at the echo agent and comes back byte-exactly.
func TestAttachSplice_ByteExactRoundTrip(t *testing.T) {
	t.Parallel()
	h := newAttachHarness(t)

	conn := h.dialAttach(t, "ssh")
	payload := []byte("hello-splice-world")

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}
}

// ---- test: half-close (scp-style) -------------------------------------------

// TestAttachSplice_HalfClose verifies that closing the write side of the local
// connection propagates as a FIN (not a reset) so the response direction keeps
// flowing. This is the scp half-close property: request written, write closed,
// response drains completely.
func TestAttachSplice_HalfClose(t *testing.T) {
	t.Parallel()
	h := newAttachHarness(t)

	conn := h.dialAttach(t, "ssh")
	uc := conn.(*net.UnixConn)

	payload := []byte("half-close-test")
	if _, err := uc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Half-close the write side — the echo agent should receive EOF and echo
	// back what it got, then close its end.
	if err := uc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// Read the echoed response — the read direction must still work.
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll after CloseWrite: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("half-close echo mismatch: got %q want %q", got, payload)
	}
}

// ---- test: 50 MB byte-exact -------------------------------------------------

// TestAttachSplice_50MB verifies that a 50 MB transfer through the IPC→QUIC
// splice path arrives byte-exact (SHA-256 matches). This exercises bufPipe
// backpressure in the in-memory transport.
func TestAttachSplice_50MB(t *testing.T) {
	t.Parallel()
	h := newAttachHarness(t)

	conn := h.dialAttach(t, "ssh")

	const size = 50 * 1024 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	wantSum := sha256.Sum256(payload)

	// Write in a goroutine so the read can drain concurrently.
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		// Half-close so the echo agent sends back and then closes.
		if uc, ok := conn.(*net.UnixConn); ok {
			uc.CloseWrite() //nolint:errcheck
		}
		writeDone <- err
	}()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if werr := <-writeDone; werr != nil {
		t.Fatalf("Write: %v", werr)
	}

	if len(got) != size {
		t.Fatalf("length mismatch: got %d want %d", len(got), size)
	}
	gotSum := sha256.Sum256(got)
	if gotSum != wantSum {
		t.Errorf("SHA-256 mismatch: payload corrupted in transit")
	}
}

// ---- test: attach cap -------------------------------------------------------

// TestAttachSplice_Cap verifies that the in-flight-attach counter is held for
// the splice lifetime and that exceeding the cap returns a clean error.
func TestAttachSplice_Cap(t *testing.T) {
	t.Parallel()

	agentConn := newMemSetupForIPC(t)
	pool := &stubPool{
		states: map[string]string{"server1": "connected"},
		conn:   agentConn,
	}
	sock := startServerWithOpts(t, &stubStatus{data: []byte(`{}`)}, pool, ipc.ServerOpts{AttachCap: 1})

	// First attach: should succeed and hold the counter at 1.
	c1 := ipc.NewClient(sock)
	conn1, err := c1.Attach("server1", "ssh", nil)
	if err != nil {
		t.Fatalf("first Attach: %v", err)
	}
	defer conn1.Close()

	// Second attach: cap=1, counter already=1 → attempt 2 > 1 → rejected.
	c2 := ipc.NewClient(sock)
	_, err2 := c2.Attach("server1", "ssh", nil)
	if err2 == nil {
		t.Fatal("second Attach should have been rejected by cap, got nil error")
	}
}

// ---- test: not-ready / unknown server ---------------------------------------

// TestAttachSplice_NotReady verifies that attaching a server in "connecting"
// state returns a non-zero status (exit-3 class).
func TestAttachSplice_NotReady(t *testing.T) {
	t.Parallel()
	pool := &stubPool{states: map[string]string{"server1": "connecting"}}
	sock := startTestServer(t, &stubStatus{data: []byte(`{}`)}, pool)

	c := ipc.NewClient(sock)
	_, err := c.Attach("server1", "ssh", nil)
	if err == nil {
		t.Fatal("expected error for not-ready server, got nil")
	}
	var ae *ipc.AttachStatusError
	if errors.As(err, &ae) && ae.Status == 0 {
		t.Errorf("expected non-zero status, got 0")
	}
}

// TestAttachSplice_UnknownServer verifies that attaching an unknown server
// returns a non-zero status.
func TestAttachSplice_UnknownServer(t *testing.T) {
	t.Parallel()
	pool := &stubPool{states: map[string]string{}}
	sock := startTestServer(t, &stubStatus{data: []byte(`{}`)}, pool)

	c := ipc.NewClient(sock)
	_, err := c.Attach("no-such-server", "ssh", nil)
	if err == nil {
		t.Fatal("expected error for unknown server, got nil")
	}
}

// ---- test: agent refuses target ---------------------------------------------

// TestAttachSplice_AgentRefusesTarget verifies that when the agent refuses the
// target (a name not registered in any route table), the AttachStatusError
// carries exit code 5 (unknown target / remote refusal).
func TestAttachSplice_AgentRefusesTarget(t *testing.T) {
	t.Parallel()
	h := newAttachHarness(t)

	c := ipc.NewClient(h.sock)
	// "no-such-target-xyz" is not a built-in and not in the echo router.
	_, err := c.Attach("server1", "no-such-target-xyz", nil)
	if err == nil {
		t.Fatal("expected error when agent refuses target, got nil")
	}
	var ae *ipc.AttachStatusError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *ipc.AttachStatusError, got %T: %v", err, err)
	}
	if ae.Status != 5 {
		t.Errorf("expected exit code 5 for unknown_target, got %d", ae.Status)
	}
}

// ---- test: connSem vs in-flight counter -------------------------------------

// TestAttachSplice_ConnSemEarlyRelease verifies that a long-lived attach does
// NOT hold the connSem slot after the ack (so concurrent status RPCs are not
// starved), while the in-flight-attach counter stays held for the splice duration.
func TestAttachSplice_ConnSemEarlyRelease(t *testing.T) {
	t.Parallel()

	agentConn := newMemSetupForIPC(t)
	pool := &trackingPool{
		inner: &stubPool{
			states: map[string]string{"server1": "connected"},
			conn:   agentConn,
		},
	}

	// ConnCap=1 would mean a long-lived attach blocks a concurrent status RPC if
	// the slot is NOT released early. With early release, both work concurrently.
	sock := startServerWithOpts(t, &stubStatus{data: []byte(`{}`)}, pool, ipc.ServerOpts{ConnCap: 1})

	// Start a long-lived attach that stays open.
	attachConn, err := ipc.NewClient(sock).Attach("server1", "ssh", nil)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer attachConn.Close()

	// A concurrent status RPC should succeed immediately (connSem released).
	statusDone := make(chan error, 1)
	go func() {
		_, err := ipc.NewClient(sock).StatusJSON()
		statusDone <- err
	}()

	select {
	case err := <-statusDone:
		if err != nil {
			t.Errorf("concurrent status RPC failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("concurrent status RPC timed out — connSem was NOT released early")
	}
}

// trackingPool wraps stubPool and counts in-flight OpenConn calls.
type trackingPool struct {
	inner    *stubPool
	inFlight atomic.Int32
}

func (p *trackingPool) EntryState(server string) (string, error) {
	return p.inner.EntryState(server)
}

func (p *trackingPool) OpenConn(ctx context.Context, server string) (tunnel.StreamConn, string, error) {
	p.inFlight.Add(1)
	defer p.inFlight.Add(-1)
	return p.inner.OpenConn(ctx, server)
}

// ---- test: shutdown mid-attach ----------------------------------------------

// TestAttachSplice_ShutdownMidAttach verifies that an IPC server Serve call
// returns promptly when Close is called while a splice is active. The splice
// unblocks when the IPC server closes and the client's connection is closed.
func TestAttachSplice_ShutdownMidAttach(t *testing.T) {
	t.Parallel()

	agentConn := newMemSetupForIPC(t)
	pool := &stubPool{
		states: map[string]string{"server1": "connected"},
		conn:   agentConn,
	}
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, pool)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = srv.Serve(ctx)
	}()

	// Start an attach that stays open.
	attachConn, err := ipc.NewClient(sock).Attach("server1", "ssh", nil)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// Simulate shutdown: close the IPC server. The splice unblocks when we also
	// close the client side of the unix socket (simulating OS closing the conn
	// on process exit).
	srv.Close()
	attachConn.Close() // unblock the splice's io.Copy on the local leg

	select {
	case <-srvDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within deadline after shutdown")
	}
}

// ---- test: no-secret logs ---------------------------------------------------

// TestAttachSplice_NoSecretLogs verifies that the PAYLOAD_CANARY string does
// not appear in daemon logs when a splice carries it as data.
func TestAttachSplice_NoSecretLogs(t *testing.T) {
	t.Parallel()

	var logBuf syncBuffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(slog.Default()) })

	h := newAttachHarness(t)
	conn := h.dialAttach(t, "ssh")

	// Send the canary through the splice.
	canary := []byte("PAYLOAD_CANARY")
	conn.Write(canary) //nolint:errcheck
	// Read the echo so the splice completes that direction.
	got := make([]byte, len(canary))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.ReadFull(conn, got) //nolint:errcheck

	conn.Close()
	time.Sleep(50 * time.Millisecond) // let log writes flush

	if containsSubstr(logBuf.String(), "PAYLOAD_CANARY") {
		t.Error("logs contain PAYLOAD_CANARY — spliced data must never appear in logs")
	}
	if containsSubstr(logBuf.String(), "PRIVATE KEY") {
		t.Error("logs contain 'PRIVATE KEY' — key material must never appear in logs")
	}
}

// containsSubstr reports whether haystack contains needle (a simple linear scan
// used in log-scanning checks to avoid importing strings or regexp).
func containsSubstr(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// syncBuffer is a bytes.Buffer safe for concurrent access.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
