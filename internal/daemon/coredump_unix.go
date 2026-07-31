//go:build linux || darwin || freebsd || openbsd || netbsd

package daemon

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// disableCoreDump sets the core-dump resource limit to zero for the current
// process, preventing the kernel from writing a core file if the daemon crashes.
//
// This removes the accidental-core-file key-leak path: if the process crashes
// while the Ed25519 private key is resident in memory, no core file is written
// that could expose it. It does NOT defend against a same-uid debugger that
// uses ptrace or /proc/<pid>/mem — a process running as the operator can read
// the key file directly regardless. This is strictly about accidents (crash
// files in shared crash directories, files sent to a crash reporter, etc.).
//
// mlock (preventing key pages from being swapped) is deliberately NOT
// implemented here. mlock is fiddlier (locked-memory limits, Go GC may copy
// pages), adds complexity, and still does not protect against a same-uid
// debugger. It is documented as a possible future addition if swap-file
// persistence becomes a concern; the additional complexity is not justified
// by the marginal security gain in the current single-operator trust model.
func disableCoreDump() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("daemon: disable core dumps: %w", err)
	}
	return nil
}
