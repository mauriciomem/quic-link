//go:build linux || darwin || freebsd || openbsd || netbsd

package daemon

// coredump_unix_test.go verifies that disableCoreDump() drives the process's
// RLIMIT_CORE current limit (Cur) to zero on the supported Unix platforms.
//
// IMPORTANT — read before modifying this test:
//
// disableCoreDump calls unix.Setrlimit(RLIMIT_CORE, {Cur:0, Max:0}).
// That call is PROCESS-WIDE AND IRREVERSIBLE within this test binary:
// once the hard limit (Max) is lowered to zero, the kernel will not allow
// it to be raised again without elevated capability (CAP_SYS_RESOURCE on
// Linux, or running as root). Any test that runs in the same process after
// this one will also have core dumps disabled.
//
// Consequences:
//   - This test MUST NOT use t.Parallel() — a parallel call to Setrlimit
//     from a goroutine on a platform where RLIMIT_CORE is per-thread
//     (historically Linux pre-3.x) could race with test state, but more
//     importantly the call is inherently process-global so ordering it
//     relative to other tests is meaningless if run concurrently.
//   - We assert Cur == 0, NOT Max == 0: on some platforms raising Max to
//     a large value and then setting Max = 0 in the same call may behave
//     differently, and the value we care about for crash-file prevention
//     is Cur, not Max.
//   - This test intentionally runs in package daemon (white-box) so it
//     can access the unexported disableCoreDump function.

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestDisableCoreDump verifies that disableCoreDump zeroes the current
// (Cur) RLIMIT_CORE limit, which prevents the kernel from writing a core
// file when the process crashes.
//
// Pre-change failure mode: no test existed; a regression that accidentally
// removed the Setrlimit call would go undetected until a crash produced a
// core file containing key material.
//
// WARNING: this test permanently lowers RLIMIT_CORE.Max for the entire
// test binary process — see the package-level comment above.
func TestDisableCoreDump(t *testing.T) {
	// NOT parallel — see the module-level comment above.

	if err := disableCoreDump(); err != nil {
		t.Fatalf("disableCoreDump() returned error: %v", err)
	}

	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatalf("Getrlimit(RLIMIT_CORE): %v", err)
	}

	// Assert Cur, not Max. Cur is the enforced limit; Max is the ceiling
	// the process could raise Cur to. On some platforms Max after
	// Setrlimit({Cur:0, Max:0}) may differ from zero due to capability
	// rules — we care only that the kernel will refuse to write a core file,
	// which it will when Cur == 0.
	if lim.Cur != 0 {
		t.Errorf("RLIMIT_CORE.Cur = %d after disableCoreDump(); want 0", lim.Cur)
	}
}
