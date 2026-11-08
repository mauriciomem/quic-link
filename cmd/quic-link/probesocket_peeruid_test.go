/**
 * @spec-handoff
 * @interface
 *   // cmd/quic-link/daemoncmd.go (unexported, test-swappable, no new public API):
 *   var newProbeClient = func(sock string) *ipc.Client { return ipc.NewClient(sock) }
 *   // probeSocketForRole must obtain its client from newProbeClient(sock)
 *   // instead of calling ipc.NewClient directly. probeSocket(sock) already
 *   // delegates to probeSocketForRole(sock, "daemon"), so it is covered too.
 *   // Tests swap it (and restore it in t.Cleanup) to inject
 *   //   ipc.NewClientWithOpts(sock, ipc.ClientOpts{UID: os.Getuid() + 99999})
 *   // which behaves like a client facing a live owner running as another uid.
 * @behavior
 *   - When Probe returns an error satisfying errors.Is(err, ipc.ErrPeerUIDMismatch)
 *     (the live owner's uid differs, or could not be verified), the probe
 *     returns (false, *errSquatterType) — exit code 2 via exitCodeForError —
 *     whose reason names the cause. Required: the error text contains the
 *     substring "different uid" and does NOT contain
 *     "probe failed with unexpected error". Only the substring is pinned; the
 *     rest of the wording is free.
 *   - The socket file is left in place and the owner keeps serving: it is
 *     never reclaimed or unlinked (canReclaim is false).
 *   - The role label still applies: role "agent" yields text containing
 *     "agent"; role "" / "daemon" adds no label.
 *   - Check order matters: the mismatch test must come before the generic
 *     fallthrough, and ErrDaemonAbsent / ErrSchemaMismatch handling is
 *     unchanged.
 * @edge-cases
 *   - Every other squatter (garbled bytes, timeout, unexpected close) keeps its
 *     byte-identical text: reason "probe failed with unexpected error: <err>".
 *   - Live conforming same-uid owner is still *errOwnerRunningType (exit 3);
 *     that is covered by the existing single-instance tests.
 * @see ./daemoncmd.go (probeSocketForRole, errSquatterType)
 * @see ./probesocket_role_test.go (roleTestSockPath, role wording tests)
 * @see ./single_instance_test.go (startTestDaemon)
 */
package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// useCrossUIDProbeClient swaps the probe-client constructor so every probe
// behaves as if the live owner ran under another uid. It returns a restore
// function (also registered with t.Cleanup, so calling it is optional). The
// swap mutates package state, so callers must not run in parallel.
func useCrossUIDProbeClient(t *testing.T) (restore func()) {
	t.Helper()
	orig := newProbeClient
	newProbeClient = func(sock string) *ipc.Client {
		return ipc.NewClientWithOpts(sock, ipc.ClientOpts{UID: os.Getuid() + 99999})
	}
	restore = func() { newProbeClient = orig }
	t.Cleanup(restore)
	return restore
}

// TestProbeSocket_CrossUIDOwnerIsSquatterAndNotReclaimed proves that a live,
// conforming owner whose uid differs from ours is reported as an occupied
// socket with a reason that says so — not as the generic probe failure — and
// that its socket is neither reclaimed nor unlinked.
func TestProbeSocket_CrossUIDOwnerIsSquatterAndNotReclaimed(t *testing.T) {
	sock := roleTestSockPath(t)
	cancel, done := startTestDaemon(t, sock)
	defer func() {
		cancel()
		<-done
	}()

	restore := useCrossUIDProbeClient(t)

	probes := []struct {
		name      string
		probe     func() (bool, error)
		wantLabel string // "" means no role label is expected
	}{
		{"probeSocket", func() (bool, error) { return probeSocket(sock) }, ""},
		{"probeSocketForRole daemon", func() (bool, error) { return probeSocketForRole(sock, "daemon") }, ""},
		{"probeSocketForRole agent", func() (bool, error) { return probeSocketForRole(sock, "agent") }, "agent"},
	}
	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			canReclaim, err := tc.probe()

			if canReclaim {
				t.Error("a live owner's socket must not be reclaimable, even when its uid differs")
			}
			var squatter *errSquatterType
			if !errors.As(err, &squatter) {
				t.Fatalf("a cross-uid owner must yield *errSquatterType, got %T: %v", err, err)
			}
			if code := exitCodeForError(err); code != 2 {
				t.Errorf("a cross-uid owner must map to exit 2, got %d", code)
			}
			if !strings.Contains(err.Error(), "different uid") {
				t.Errorf("the error must say the owner runs as a different uid, got: %v", err)
			}
			if strings.Contains(err.Error(), "probe failed with unexpected error") {
				t.Errorf("a cross-uid owner must not get the generic probe-failure reason, got: %v", err)
			}
			if tc.wantLabel != "" && !strings.Contains(err.Error(), tc.wantLabel) {
				t.Errorf("the role label %q must still appear, got: %v", tc.wantLabel, err)
			}
			if _, statErr := os.Stat(sock); statErr != nil {
				t.Errorf("the socket must stay in place after a cross-uid probe: %v", statErr)
			}
		})
	}

	// The owner must still be alive and serving after all of the above, which
	// a reclaim/unlink would have broken. Probe it with the real client.
	restore()
	if perr := ipc.NewClient(sock).Probe(2 * time.Second); perr != nil {
		t.Errorf("the owner must still answer a same-uid probe after cross-uid probes, got: %v", perr)
	}
}

// TestProbeSocketForRole_GarbledSquatterReasonUnchanged is the regression
// guard for the other direction: a squatter that is not a uid mismatch keeps
// the generic reason, so the cross-uid wording cannot leak onto it.
func TestProbeSocketForRole_GarbledSquatterReasonUnchanged(t *testing.T) {
	sock := roleTestSockPath(t)

	startGarbledSquatter(t, sock)

	for _, role := range []string{"", "daemon", "agent"} {
		canReclaim, perr := probeSocketForRole(sock, role)
		if canReclaim {
			t.Errorf("role %q: a squatter-held socket must not be reclaimable", role)
		}
		var squatter *errSquatterType
		if !errors.As(perr, &squatter) {
			t.Fatalf("role %q: garbled squatter must yield *errSquatterType, got %T: %v", role, perr, perr)
		}
		if !strings.Contains(perr.Error(), "probe failed with unexpected error") {
			t.Errorf("role %q: a non-uid squatter must keep the generic reason, got: %v", role, perr)
		}
		if strings.Contains(perr.Error(), "different uid") {
			t.Errorf("role %q: a non-uid squatter must not be described as a different uid, got: %v", role, perr)
		}
	}
}
