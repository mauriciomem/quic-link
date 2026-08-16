package main

// The socket a connection goes out on has to be in the same address family as
// the address it is going to. Getting that wrong does not produce a clear
// error: the send is refused with a message about the address rather than the
// socket, or worse, on some platforms it is accepted and the datagram never
// arrives.
//
// These read the family back from the operating system rather than trusting the
// call that opened the socket, for the same reason the other socket-family
// checks do: the network string and the family a socket ends up in are not the
// same thing.

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// requireIPv6 skips a test on a machine with no IPv6 at all, so the result says
// "not tested here" rather than reporting a failure that belongs to the
// machine. It opens a real socket rather than reading configuration, because
// what matters is whether one can be opened.
func requireIPv6(t *testing.T) {
	t.Helper()
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("this machine cannot open an IPv6 socket, so there is nothing to check: %v", err)
	}
	c.Close()
}

func TestTheDialingSocketMatchesTheAddressItWillDial(t *testing.T) {
	requireIPv6(t)

	cases := []struct {
		name string
		addr string
		want string
	}{
		{"IPv6 literal", "[fd3e:5c82:9b1a:1::20]:7443", "IPv6"},
		{"IPv6 loopback", "[::1]:7443", "IPv6"},
		{"link-local with an interface name", "[fe80::1%lo]:7443", "IPv6"},
		{"IPv4 literal", "198.51.100.1:7443", "IPv4"},
		{"IPv4 written in IPv6 form", "[::ffff:198.51.100.1]:7443", "IPv4"},
		{"a name", "agent.example.com:7443", "IPv4"},
		{"not an address", "this is not an address at all", "IPv4"},
	}

	for _, tc := range cases {
		conn, err := bindDialingSocket(tc.addr)
		if err != nil {
			t.Errorf("%s: opening a socket for %q: %v", tc.name, tc.addr, err)
			continue
		}
		got := socketFamily(t, conn)
		conn.Close()
		if got != tc.want {
			t.Errorf("%s: a connection to %q would go out on an %s socket, want %s; a socket in "+
				"the wrong family cannot carry the address it was opened for",
				tc.name, tc.addr, got, tc.want)
		}
	}
}

// TestAServerReachedOverIPv6GetsAnIPv6Socket checks the daemon's own path, which
// is the one that has an address to consult. A socket opened without looking at
// the address would pass the check above and still be wrong here.
func TestAServerReachedOverIPv6GetsAnIPv6Socket(t *testing.T) {
	requireIPv6(t)

	conn, err := bindServerSocket("probe", config.Server{Addr: "[fd3e:5c82:9b1a:1::20]:7443"}, false)
	if err != nil {
		t.Fatalf("opening the socket for an IPv6 server: %v", err)
	}
	defer conn.Close()

	if got := socketFamily(t, conn); got != "IPv6" {
		t.Errorf("a server named by an IPv6 address got an %s socket, want IPv6; the address it "+
			"was opened for is not being consulted", got)
	}
}

// TestAConnectionCompletesOverIPv6 is the end-to-end check: an agent listening
// on an IPv6 address, reached over IPv6, through the same code a user's command
// runs. The checks above prove the socket is the right kind; this proves the
// right kind is enough to carry a session.
func TestAConnectionCompletesOverIPv6(t *testing.T) {
	requireIPv6(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	agentKey, agentPin := stdioAuthGenIdentity(t)
	clientKey, clientPin := stdioAuthGenIdentity(t)

	agentTLS, err := identity.ServerTLS(agentKey, []string{clientPin})
	if err != nil {
		t.Fatalf("agent TLS: %v", err)
	}

	// The agent waits on the IPv6 loopback, so reaching it is only possible
	// over IPv6. Port 0 lets the kernel choose, and the listener reports back
	// what it took.
	agentUDP, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("agent socket: %v", err)
	}
	t.Cleanup(func() { agentUDP.Close() })

	agentTr, err := transport.NewQUICListenTransport(agentUDP, agentTLS, nil)
	if err != nil {
		t.Fatalf("agent transport: %v", err)
	}
	t.Cleanup(func() { agentTr.Close() })

	ln, err := agentTr.Listen()
	if err != nil {
		t.Fatalf("agent listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "client.pem")
	if err := identity.WriteKey(keyFile, clientKey); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	addr := ln.Addr().String()
	if !strings.Contains(addr, "::1") {
		t.Fatalf("the agent is listening on %q, which is not the IPv6 loopback this test needs", addr)
	}

	// pingRun opens its own socket the same way every outgoing connection does,
	// so this exercises the choice under test rather than a test-only path.
	if err := pingRun(ctx, addr, 1, keyFile, agentPin); err != nil {
		t.Fatalf("reaching an agent at %s over IPv6 failed: %v", addr, err)
	}
}
