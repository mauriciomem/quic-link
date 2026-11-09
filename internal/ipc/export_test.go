package ipc

import (
	"net"
	"testing"
)

// RealPeerUID is the peer-credential reader the client uses in production.
// Tests that swap the client's reader use it as a pass-through to keep the
// rest of the dial path honest.
var RealPeerUID = peerUID

// SetClientPeerUIDForTest replaces the function Client.dial() uses to read
// the far end's uid for the duration of the test and restores the original
// in t.Cleanup. It never affects the server's own peer-cred check. Because it
// mutates a package-level variable, tests that call it must not run in
// parallel.
func SetClientPeerUIDForTest(t testing.TB, fn func(net.Conn) (uint32, error)) {
	t.Helper()
	orig := clientPeerUID
	clientPeerUID = fn
	t.Cleanup(func() { clientPeerUID = orig })
}
