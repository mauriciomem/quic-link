/**
 * @spec-handoff
 * @interface
 *   type ClientOpts struct { UID int } // 0 = default to os.Getuid(), mirrors ServerOpts
 *   func NewClientWithOpts(path string, opts ClientOpts) *Client
 *   // NewClient(path) remains untouched and behaves as NewClientWithOpts(path, ClientOpts{}).
 * @behavior
 *   - Client.dial() calls peerUID(conn) on the freshly dialed conn (mirroring
 *     handleConn's server-side use of peerUID) and compares it against the
 *     client's expected uid (opts.UID, defaulting to os.Getuid()).
 *   - A same-uid peer: dial() succeeds unchanged (default, single-operator path).
 *   - A peer whose uid does not match the expected uid: dial() returns an error
 *     BEFORE any request is written or any response is trusted — the caller must
 *     never see the peer's response body/status on a uid mismatch.
 *   - That error must be distinguishable from ErrDaemonAbsent and
 *     ErrSchemaMismatch (a live, conforming daemon speaking the right schema is
 *     neither "absent" nor "schema-mismatched" — it is a wrong peer). Whether
 *     this is a new sentinel or a typed error is an implementation choice; this
 *     test asserts errors.Is(err, ErrPeerUIDMismatch) and that errors.Is is
 *     false for both existing sentinels.
 * @edge-cases
 *   - Same-uid squatter (plan 06 Finding E9-F1 / Finding 1 B3/B4): a same-uid
 *     process listening on the socket path passes every directory-permission
 *     check and this uid check too — this fix does NOT raise the ceiling against
 *     that adversary (documented as an accepted boundary on the server side via
 *     peerUID's own doc comment). This test only proves the DIFFERENT-uid case
 *     is now rejected, which is what closes the "no verification of the far end
 *     at all" gap Finding 1 describes as a precondition for agent.sock.
 *   - This file intentionally fails to COMPILE against current
 *     internal/ipc/client.go, not merely fails at runtime: dial() has no hook
 *     today to be told "expect a uid other than the real one" (unlike the
 *     server side, which already has ServerOpts.UID). Introducing
 *     ClientOpts/NewClientWithOpts is itself part of the E2 fix, so
 *     TestClientDial_WrongPeerUIDRejected necessarily references API that does
 *     not exist until E2 lands. Do NOT stub ClientOpts as a no-op just to make
 *     this file build early — that would make the wrong-uid subtest pass
 *     vacuously instead of failing honestly. RED for this step IS the compiler
 *     error; GREEN is this file building and both subtests passing after E2.
 * @see ./server_hardening_test.go (TestPeerCred_SameUidPasses / TestPeerCred_WrongUidRejected —
 *      the server-side precedent this file mirrors from the client's side of the dial)
 * @see ./server.go (ServerOpts/NewServerWithOpts — the pattern ClientOpts/NewClientWithOpts mirrors)
 * @see ./peercred_linux.go (peerUID — reused in the reverse direction by E2's fix)
 */
package ipc_test

import (
	"errors"
	"os"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// TestClientDial_SameUIDStillSucceeds is a regression guard for the default,
// single-operator path: a client with no uid override dialing a server
// running as the same uid must keep working exactly as it does today. This
// must pass both before and after E2 — it is what proves the fix does not
// regress the common case. It uses only API that already exists (NewClient,
// startHardenedServer, ServerOpts{}) so it compiles and passes right now.
func TestClientDial_SameUIDStillSucceeds(t *testing.T) {
	sock := startHardenedServer(t,
		&stubStatus{data: []byte(`{"schema":1}`)},
		&stubPool{},
		ipc.ServerOpts{}, // default uid = current process uid
	)

	c := ipc.NewClient(sock)
	if _, err := c.StatusJSON(); err != nil {
		t.Fatalf("same-uid dial should succeed, got: %v", err)
	}
}

// TestClientDial_WrongPeerUIDRejected proves Client.dial() does not currently
// verify the peer's uid: it starts a real, conforming server — answering
// correctly, running as the actual current test-process uid, a legitimate
// listener rather than a squatter — and dials it with a client configured to
// expect a deliberately wrong uid. This mirrors
// TestPeerCred_WrongUidRejected's trick of using os.Getuid()+99999 (a uid
// that cannot legitimately be the peer) rather than forking a real
// different-uid process.
//
// This subtest references the not-yet-existing ipc.NewClientWithOpts /
// ipc.ClientOpts, so the whole file fails to compile against current
// internal/ipc/client.go. That compile failure IS this step's RED state —
// see the @spec-handoff block above and e1-client-peercred-failing-test.md's
// Notes section for why a signature-introducing addition takes this shape.
func TestClientDial_WrongPeerUIDRejected(t *testing.T) {
	myUID := os.Getuid()
	wrongUID := myUID + 99999

	// A real, conforming server, running as the actual current uid — the
	// client is the one with the wrong expectation, not the server.
	sock := startHardenedServer(t,
		&stubStatus{data: []byte(`{"schema":1}`)},
		&stubPool{},
		ipc.ServerOpts{}, // default uid = current process uid (a legit listener)
	)

	c := ipc.NewClientWithOpts(sock, ipc.ClientOpts{UID: wrongUID})
	_, err := c.StatusJSON()

	if err == nil {
		t.Fatal("expected an error when the peer's uid does not match the client's expected uid, got nil")
	}
	if !errors.Is(err, ipc.ErrPeerUIDMismatch) {
		t.Errorf("peer-uid mismatch must satisfy errors.Is(err, ErrPeerUIDMismatch), got: %v", err)
	}
	if errors.Is(err, ipc.ErrDaemonAbsent) {
		t.Errorf("peer-uid mismatch against a live daemon must not be reported as ErrDaemonAbsent, got: %v", err)
	}
	if errors.Is(err, ipc.ErrSchemaMismatch) {
		t.Errorf("peer-uid mismatch against a schema-conforming daemon must not be reported as ErrSchemaMismatch, got: %v", err)
	}
}
