//go:build !linux && !darwin && !freebsd

package ipc

import (
	"errors"
	"net"
)

// errPeerCredUnsupported is returned by peerUID on platforms where neither
// SO_PEERCRED (Linux) nor getpeereid (BSD/macOS) is available.
var errPeerCredUnsupported = errors.New("ipc: peer-cred: not supported on this platform")

// peerUID returns errPeerCredUnsupported on platforms that expose no
// peer-credential API. The caller (the accept loop) treats this as a hard
// error and refuses the connection rather than falling back to "allow
// everything." Refusing is the safe default: this tool is built for Linux and
// macOS; an unsupported platform should not silently weaken the trust boundary.
//
// If you need to run quic-link on an unsupported platform and filesystem perms
// alone are sufficient for your environment, you can change this to a log-and-
// allow, but do so with full awareness of the risk.
func peerUID(_ net.Conn) (uint32, error) {
	return 0, errPeerCredUnsupported
}
