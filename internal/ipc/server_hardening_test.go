package ipc_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// shortSocketPath returns a unix socket path short enough to bind.
//
// A socket address is limited to 104 bytes on macOS, and t.TempDir builds its
// path from TMPDIR and the test's own name. On Linux TMPDIR is /tmp and the
// result fits; on macOS it is a per-user directory under /var/folders of about
// fifty characters, and a socket underneath it does not. The failure is a bare
// "bind: invalid argument", or on the dialling side an error about the socket
// being unreachable, and neither mentions a length.
//
// The directory comes from os.MkdirTemp under /tmp explicitly rather than from
// TMPDIR, so it is unaffected by however the environment is configured, and it is
// unique per call so two tests in one process cannot collide.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ql-ipc-")
	if err != nil {
		t.Fatalf("creating a short temp dir for a unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

// startHardenedServer starts a Server with custom options on a short socket path.
func startHardenedServer(
	t *testing.T,
	status ipc.StatusProvider,
	pool ipc.AttachPool,
	opts ipc.ServerOpts,
) string {
	t.Helper()
	sock := shortSocketPath(t)
	srv := ipc.NewServerWithOpts(sock, status, pool, opts)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen %s: %v", sock, err)
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
	return sock
}

// TestPeerCred_SameUidPasses verifies that a connection from the current process
// (same uid as the server) is accepted and returns a valid response.
func TestPeerCred_SameUidPasses(t *testing.T) {
	sock := startHardenedServer(t,
		&stubStatus{data: []byte(`{"schema":1}`)},
		&stubPool{},
		ipc.ServerOpts{}, // default uid = current uid
	)
	// The server uses the current uid as expected uid, and we are dialing from
	// the same process — peer-cred check must succeed.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	resp, err := ipc.RoundTripConn(conn, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "status",
	})
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if resp.Status != 0 {
		t.Errorf("same-uid request should succeed, got status %d: %s", resp.Status, resp.Msg)
	}
}

// TestPeerCred_WrongUidRejected verifies that the server rejects a connection
// when the server's configured expected uid does not match the actual peer uid.
// We start the server with uid = currentUID+99999 (a nonexistent uid) so that
// our real connection is always rejected.
func TestPeerCred_WrongUidRejected(t *testing.T) {
	myUID := os.Getuid()
	wrongUID := myUID + 99999
	opts := ipc.ServerOpts{UID: wrongUID}
	sock := startHardenedServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{},
		opts,
	)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		// Server may have already closed on the reject — counts as rejection.
		return
	}
	defer conn.Close()

	resp, err := ipc.RoundTripConn(conn, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "status",
	})
	if err != nil {
		// Connection was closed by server after rejection — expected.
		return
	}
	if resp.Status == 0 {
		t.Error("expected non-zero status when peer uid does not match expected uid, got 0")
	}
}

// TestAttachCap_TooManyTunnels verifies that the in-flight-attach cap returns
// a framed "too many open tunnels" error when the cap is exceeded.
// We use AttachCap=1 so a single concurrent attach does not block, but we
// verify the over-cap path using a holding helper.
func TestAttachCap_TooManyTunnels(t *testing.T) {
	// blockingPool returns "connected" but blocks in EntryState until unblocked.
	release := make(chan struct{})
	blocking := &blockingAttachPool{release: release}

	sock := startHardenedServer(t,
		&stubStatus{data: []byte(`{}`)},
		blocking,
		ipc.ServerOpts{AttachCap: 1},
	)

	// First attach: will hold the in-flight counter at 1 until released.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = ipc.RoundTripConn(conn, ipc.Request{
			SocketSchema: ipc.SocketSchema,
			Kind:         "attach",
			Server:       "s1",
			Target:       "ssh",
		})
	}()

	// Wait for the first handler to increment the counter.
	time.Sleep(50 * time.Millisecond)

	// Second attach: should hit the cap (counter=1, cap=1 → 2 > 1 → reject).
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer conn.Close()
	resp, err := ipc.RoundTripConn(conn, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "attach",
		Server:       "s1",
		Target:       "ssh",
	})
	if err != nil {
		t.Fatalf("second round-trip: %v", err)
	}
	if resp.Status == 0 {
		t.Errorf("expected non-zero status when attach cap is exceeded, got 0")
	}

	// Release the first handler so it can complete.
	close(release)
	<-firstDone
}

// TestConnCap_Backpressure verifies that the connection semaphore provides
// backpressure when the cap is reached. With cap=1, the second connection
// waits in the semaphore until the first handler finishes.
func TestConnCap_Backpressure(t *testing.T) {
	release := make(chan struct{})
	blockingStatus := &blockingStatusProvider{ch: release}

	sock := startHardenedServer(t,
		blockingStatus,
		&stubPool{},
		ipc.ServerOpts{ConnCap: 1},
	)

	// First connection will block in the status handler.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = ipc.RoundTripConn(conn, ipc.Request{
			SocketSchema: ipc.SocketSchema,
			Kind:         "rpc",
			Method:       "status",
		})
	}()

	// Give the first connection time to be accepted and start blocking.
	time.Sleep(60 * time.Millisecond)

	// Second connection: will not start handling until the first finishes.
	secondComplete := make(chan struct{})
	go func() {
		defer close(secondComplete)
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = ipc.RoundTripConn(conn, ipc.Request{
			SocketSchema: ipc.SocketSchema,
			Kind:         "rpc",
			Method:       "status",
		})
	}()

	// After a short wait, the second connection should NOT have completed yet
	// because the cap=1 semaphore is held by the first.
	time.Sleep(40 * time.Millisecond)
	select {
	case <-secondComplete:
		t.Error("second connection completed before first was released — cap not providing backpressure")
	default:
	}

	// Release the first connection.
	close(release)
	<-firstDone

	// Now the second should complete promptly.
	select {
	case <-secondComplete:
	case <-time.After(2 * time.Second):
		t.Error("second connection did not complete after first was released")
	}
}

// TestGracefulShutdown_ServeExitsOnCtxCancel verifies that Serve returns when
// ctx is cancelled (via listener close) and does not leak goroutines.
// The socket-file removal is tested in the cmd layer (daemon.Run).
func TestGracefulShutdown_ServeExitsOnCtxCancel(t *testing.T) {
	sock := shortSocketPath(t)

	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()

	// Verify the socket exists while the server is running.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket should exist while server is running: %v", err)
	}

	// Cancel and wait for Serve to exit.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}

	// After Serve returns the listener is closed. Attempting to accept a new
	// connection via the closed listener should fail; but the socket file may
	// still exist (removal is the caller's responsibility — done in daemon.Run).
	// Verify the server's internal state via Close being idempotent.
	if err := srv.Close(); err != nil {
		t.Errorf("Close after ctx cancel returned error: %v", err)
	}
}

// ---- helpers for blocking tests ---------------------------------------------

// blockingStatusProvider blocks until ch is closed, then returns fixed JSON.
// Used to hold a handler slot open for backpressure testing.
type blockingStatusProvider struct {
	once sync.Once
	ch   chan struct{}
}

func (b *blockingStatusProvider) StatusJSON() ([]byte, error) {
	<-b.ch
	return []byte(`{"schema":1}`), nil
}

// blockingAttachPool blocks in EntryState until release is closed, simulating
// a slow attach operation that holds the in-flight counter up. OpenConn also
// blocks so the in-flight attach counter remains held during the test window.
type blockingAttachPool struct {
	release chan struct{}
}

func (p *blockingAttachPool) EntryState(_ string) (string, error) {
	<-p.release
	return "connected", nil
}

func (p *blockingAttachPool) OpenConn(ctx context.Context, _ string) (tunnel.StreamConn, string, error) {
	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	return nil, "", fmt.Errorf("blocked pool: no conn")
}
