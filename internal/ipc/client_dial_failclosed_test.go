/**
 * @spec-handoff
 * @interface
 *   // internal/ipc/client.go (unexported, no new public API):
 *   var clientPeerUID = peerUID            // func(net.Conn) (uint32, error)
 *   // Client.dial() must call clientPeerUID(conn) INSTEAD of peerUID(conn).
 *   // The server's handleConn keeps calling peerUID directly; the seam is
 *   // client-only so a test can fail the client's read without breaking the
 *   // in-process server's own check.
 *   // internal/ipc/export_test.go (already provided with these tests):
 *   //   var RealPeerUID = peerUID
 *   //   func SetClientPeerUIDForTest(t testing.TB, fn func(net.Conn) (uint32, error))
 *   //   — swaps clientPeerUID, restores it in t.Cleanup.
 * @behavior
 *   - If clientPeerUID returns an error (the far end's uid cannot be read),
 *     dial() fails closed: it closes the conn, writes no request frame, and
 *     returns an error satisfying errors.Is(err, ErrPeerUIDMismatch).
 *   - The underlying read error stays reachable too, i.e.
 *       fmt.Errorf("%w: peer-cred check failed: %w", ErrPeerUIDMismatch, err)
 *     so errors.Is(err, <injected error>) is also true.
 *   - If clientPeerUID succeeds but the uid differs from the expected one,
 *     dial() returns an error satisfying errors.Is(err, ErrPeerUIDMismatch),
 *     closes the conn and writes no request frame (unchanged behavior).
 *   - If clientPeerUID succeeds with the expected uid, requests are written
 *     as before.
 *   - Every Client method funnels through dial(); the tests cover StatusJSON
 *     and Probe.
 * @edge-cases
 *   - Neither failure may be reported as ErrDaemonAbsent or ErrSchemaMismatch.
 *   - Positive control: with the seam swapped to the real reader, a request
 *     does reach the far end, so the "no bytes" assertions are not vacuous.
 * @see ./client.go (dial)
 * @see ./client_dial_peercred_test.go (the same-uid and wrong-uid cases)
 */
package ipc_test

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// connRecord is what a recorderServer observed on one accepted connection.
type connRecord struct {
	bytes int   // total bytes the client wrote before the conn ended
	err   error // error that ended the read; nil means a clean EOF
}

// startRecorderServer listens on a short unix socket and, for every accepted
// connection, counts the bytes the client writes until the client closes its
// end. It never replies. It lets a test observe, from the far end, both
// whether a request frame was written and whether the client closed the conn.
func startRecorderServer(t *testing.T) (sock string, records <-chan connRecord) {
	t.Helper()
	sock = shortSocketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	ch := make(chan connRecord, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				n, rerr := io.Copy(io.Discard, c)
				ch <- connRecord{bytes: int(n), err: rerr}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return sock, ch
}

// waitRecord returns the next connection record or fails the test if the far
// end never sees the connection end.
func waitRecord(t *testing.T, records <-chan connRecord) connRecord {
	t.Helper()
	select {
	case r := <-records:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("the far end never saw the client connection end: the client did not close it")
		return connRecord{}
	}
}

// clientCalls are the Client methods exercised through the dial chokepoint.
var clientCalls = []struct {
	name string
	call func(c *ipc.Client) error
}{
	{"StatusJSON", func(c *ipc.Client) error { _, err := c.StatusJSON(); return err }},
	{"Probe", func(c *ipc.Client) error { return c.Probe(2 * time.Second) }},
}

// TestClientDial_UnreadablePeerCredFailsClosed proves that when the client
// cannot read the far end's uid, it refuses to proceed: the error is the
// peer-uid-mismatch sentinel (with the underlying cause still reachable), the
// connection is closed, and no request frame is ever written.
func TestClientDial_UnreadablePeerCredFailsClosed(t *testing.T) {
	for _, tc := range clientCalls {
		t.Run(tc.name, func(t *testing.T) {
			sock, records := startRecorderServer(t)

			errInjected := errors.New("injected peer-cred read failure")
			var dialed net.Conn
			ipc.SetClientPeerUIDForTest(t, func(c net.Conn) (uint32, error) {
				dialed = c
				return 0, errInjected
			})

			err := tc.call(ipc.NewClient(sock))

			if err == nil {
				t.Fatal("expected an error when the peer's uid cannot be read, got nil")
			}
			if !errors.Is(err, ipc.ErrPeerUIDMismatch) {
				t.Errorf("an unverifiable peer must satisfy errors.Is(err, ErrPeerUIDMismatch), got: %v", err)
			}
			if !errors.Is(err, errInjected) {
				t.Errorf("the underlying read error must stay reachable via errors.Is, got: %v", err)
			}
			if errors.Is(err, ipc.ErrDaemonAbsent) || errors.Is(err, ipc.ErrSchemaMismatch) {
				t.Errorf("an unverifiable live peer must not be reported as absent or schema-mismatched, got: %v", err)
			}

			// The far end must see the connection end without having been sent
			// a single byte.
			rec := waitRecord(t, records)
			if rec.bytes != 0 {
				t.Errorf("no request may be written to an unverifiable peer, far end received %d bytes", rec.bytes)
			}

			// The client's own handle on the connection must be closed.
			if dialed == nil {
				t.Fatal("the peer-cred reader was never called with the dialed conn")
			}
			if _, rerr := dialed.Read(make([]byte, 1)); !errors.Is(rerr, net.ErrClosed) {
				t.Errorf("the dialed conn must be closed on a failed peer-cred read, Read returned: %v", rerr)
			}
		})
	}
}

// TestClientDial_ReadablePeerCredStillWritesRequest is the positive control
// for the fail-closed test: with the same harness and the seam swapped to the
// real reader (no failure injected), the request does reach the far end and
// the error is not a peer-uid mismatch. Without this, "zero bytes received"
// above could be an artifact of the harness rather than of the fix.
func TestClientDial_ReadablePeerCredStillWritesRequest(t *testing.T) {
	sock, records := startRecorderServer(t)
	ipc.SetClientPeerUIDForTest(t, ipc.RealPeerUID)

	// The recorder never replies, so Probe ends on its own short deadline and
	// closes the conn, which lets the recorder report what it received.
	err := ipc.NewClient(sock).Probe(200 * time.Millisecond)

	if errors.Is(err, ipc.ErrPeerUIDMismatch) {
		t.Errorf("a readable, matching peer must not be reported as a uid mismatch, got: %v", err)
	}
	rec := waitRecord(t, records)
	if rec.bytes == 0 {
		t.Error("with a readable, matching peer the request must reach the far end, received 0 bytes")
	}
}

// TestClientDial_WrongPeerUIDWritesNoRequest proves the uid-mismatch path is
// also fail-closed on the wire: the client closes the conn and the far end
// never receives a request frame.
func TestClientDial_WrongPeerUIDWritesNoRequest(t *testing.T) {
	for _, tc := range clientCalls {
		t.Run(tc.name, func(t *testing.T) {
			sock, records := startRecorderServer(t)

			c := ipc.NewClientWithOpts(sock, ipc.ClientOpts{UID: os.Getuid() + 99999})
			err := tc.call(c)

			if !errors.Is(err, ipc.ErrPeerUIDMismatch) {
				t.Errorf("a peer with the wrong uid must satisfy errors.Is(err, ErrPeerUIDMismatch), got: %v", err)
			}
			rec := waitRecord(t, records)
			if rec.bytes != 0 {
				t.Errorf("no request may be written to a wrong-uid peer, far end received %d bytes", rec.bytes)
			}
		})
	}
}
