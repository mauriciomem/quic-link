package main

// socket_family_test.go checks that each UDP socket this program binds ends up
// in the address family it was meant to be in.
//
// The rule being guarded: a socket used to connect out stays IPv4-only, while a
// socket that waits for an incoming connection is dual-stack so either family
// can reach it. Both halves matter, and they fail in opposite directions, so
// each is asserted separately.
//
// Why the family is read off the kernel rather than from the network string:
// the string passed to the bind call and the family the socket actually ends up
// in are not the same thing, and the difference depends on the address. These
// tests ask the operating system what it gave us.
//
// Why every bind here uses a wildcard address: a wildcard is the only address
// that tells the two spellings apart. Binding a specific loopback address
// yields an IPv4 socket either way, so a test written that way passes whichever
// spelling the code uses, and asserts nothing. That is not a hypothetical — the
// pre-existing test for the agent's listener binds loopback, and changing that
// listener's family leaves it green.
//
// Portability: the family is read with getsockname, whose result is a different
// concrete type per family. That works the same way on every platform this
// program targets. Reading the socket domain option directly would be simpler
// but does not exist outside Linux, and a guard that compiles on one platform
// only is a guard that is absent on the other.

import (
	"net"
	"syscall"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

// socketFamily reports the address family of an already-bound UDP socket as the
// operating system sees it, independent of how the bind was spelled.
func socketFamily(t *testing.T, conn *net.UDPConn) string {
	t.Helper()

	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("cannot reach the underlying socket: %v", err)
	}

	var family string
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		sa, err := syscall.Getsockname(int(fd))
		if err != nil {
			opErr = err
			return
		}
		switch sa.(type) {
		case *syscall.SockaddrInet4:
			family = "IPv4"
		case *syscall.SockaddrInet6:
			family = "IPv6"
		default:
			family = "neither IPv4 nor IPv6"
		}
	}); err != nil {
		t.Fatalf("cannot inspect the socket: %v", err)
	}
	if opErr != nil {
		t.Fatalf("cannot read the socket's own address: %v", opErr)
	}
	return family
}

// TestDialingServerSocketIsIPv4Only covers the socket used to connect out to a
// server. It must not become dual-stack: on macOS such a socket silently fails
// to transmit to an on-link IPv4 neighbour, which looks like a broken network
// rather than a broken build.
func TestDialingServerSocketIsIPv4Only(t *testing.T) {
	// The address is never dialled here; only the local socket is bound. It is
	// a documentation-range address so it cannot resolve to anything real.
	conn, err := bindServerSocket("probe", config.Server{Addr: "198.51.100.1:7443"}, false)
	if err != nil {
		t.Fatalf("binding the socket used to connect out: %v", err)
	}
	defer conn.Close()

	if got := socketFamily(t, conn); got != "IPv4" {
		t.Errorf("the socket used to connect out is %s, want IPv4 only; a dual-stack "+
			"socket here fails silently against on-link IPv4 peers on some platforms", got)
	}
}

// TestWaitingServerSocketIsDualStack covers the socket that waits for a server
// to connect to us. It must stay dual-stack, or the program stops being
// reachable over IPv6 while still appearing to work.
//
// The wildcard port matters: with a specific loopback address this socket is
// IPv4 whichever spelling is used, and the assertion would prove nothing.
func TestWaitingServerSocketIsDualStack(t *testing.T) {
	conn, err := bindServerSocket("probe", config.Server{Listen: ":0"}, true)
	if err != nil {
		t.Fatalf("binding the socket that waits for a connection: %v", err)
	}
	defer conn.Close()

	if got := socketFamily(t, conn); got != "IPv6" {
		t.Errorf("the socket that waits for a connection is %s, want dual-stack; "+
			"an IPv4-only socket here is unreachable over IPv6", got)
	}
}

// TestALoopbackAddressHidesTheSocketFamily records why the tests above bind a
// wildcard address, as something that runs rather than something written down.
//
// Binding a specific loopback address produces an IPv4 socket regardless of
// which spelling the code used, so the two cannot be told apart. Any future
// family guard that binds loopback is therefore already broken, and this test
// exists so that discovery costs one test run instead of one investigation.
//
// Note this test does not fail when a bind's family is changed; it is not a
// second guard on the product. It fails only if the platform's behaviour
// changes, which would invalidate the reasoning the other two tests rest on.
func TestALoopbackAddressHidesTheSocketFamily(t *testing.T) {
	conn, err := bindServerSocket("probe", config.Server{Listen: "127.0.0.1:0"}, true)
	if err != nil {
		t.Fatalf("binding a loopback address: %v", err)
	}
	defer conn.Close()

	if got := socketFamily(t, conn); got != "IPv4" {
		t.Errorf("a dual-stack bind to a loopback address produced %s, want IPv4; "+
			"if this changed, the reasoning behind binding wildcard addresses in the "+
			"other socket-family tests needs revisiting", got)
	}
}
