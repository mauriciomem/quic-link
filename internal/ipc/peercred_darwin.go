//go:build darwin || freebsd

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective uid of the process on the other end of conn,
// which must be a *net.UnixConn. It uses the LOCAL_PEERCRED socket option,
// the BSD/macOS mechanism for querying the credentials of the connecting peer.
//
// This check is defense-in-depth ON TOP of the 0700/0600 filesystem
// permissions on the socket directory and file. It is NOT a ceiling-raise
// against a same-uid adversary (a process already running as the operator can
// read the key file directly). It only helps survive a filesystem-perms or
// TMPDIR-mode mistake — the common macOS deployment path where XDG_RUNTIME_DIR
// is absent and the socket lives under the operator's per-user temp directory.
func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("ipc: peer-cred: conn is not a *net.UnixConn (got %T)", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("ipc: peer-cred: SyscallConn: %w", err)
	}
	var uid uint32
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		xucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			innerErr = fmt.Errorf("LOCAL_PEERCRED: %w", err)
			return
		}
		uid = xucred.Uid
	}); err != nil {
		return 0, fmt.Errorf("ipc: peer-cred: Control: %w", err)
	}
	if innerErr != nil {
		return 0, fmt.Errorf("ipc: peer-cred: %w", innerErr)
	}
	return uid, nil
}
