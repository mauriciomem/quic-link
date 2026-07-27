//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective uid of the process on the other end of conn,
// which must be a *net.UnixConn. It uses SO_PEERCRED, the Linux mechanism for
// querying the credentials of the connecting peer.
//
// This check is defense-in-depth ON TOP of the 0700/0600 filesystem
// permissions on the socket directory and file. It is NOT a ceiling-raise
// against a same-uid adversary (a process already running as the operator can
// read the key file directly). It only helps survive a filesystem-perms or
// XDG_RUNTIME_DIR-mode mistake.
func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("ipc: peer-cred: conn is not a *net.UnixConn (got %T)", conn)
	}
	var uid uint32
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("ipc: peer-cred: SyscallConn: %w", err)
	}
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			innerErr = fmt.Errorf("SO_PEERCRED: %w", err)
			return
		}
		uid = ucred.Uid
	}); err != nil {
		return 0, fmt.Errorf("ipc: peer-cred: Control: %w", err)
	}
	if innerErr != nil {
		return 0, fmt.Errorf("ipc: peer-cred: %w", innerErr)
	}
	return uid, nil
}
