package main

import (
	"net"
	"net/netip"
)

// bindDialingSocket opens the local socket used to connect out to a peer, in
// the address family that peer needs.
//
// The two families get separate sockets rather than one socket carrying both.
// A socket opened for both families cannot be relied on to reach an IPv4
// neighbour on the same network segment on every platform this program runs on:
// the send is accepted and the datagram never arrives, which looks like a
// broken network rather than a broken program. Keeping the IPv4 socket exactly
// as it always was avoids that entirely, and costs one branch.
//
// The choice is made from the address as written, so it is decided before
// anything is opened and without asking the network anything. A name is treated
// as IPv4, which is what it resolves to whenever it has an address in both
// families; a name that has only an IPv6 address is a case this does not yet
// serve.
//
// Sockets that wait to be contacted are the opposite case and are opened
// elsewhere: they take both families deliberately, because the far end chooses
// which one to arrive on and refusing either would make the program
// unreachable for no reason.
func bindDialingSocket(addr string) (*net.UDPConn, error) {
	if dialsIPv6(addr) {
		return net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero})
	}
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
}

// dialsIPv6 reports whether an address is written as an IPv6 address.
//
// Only a literal answers this; a name is not resolved, because that would mean
// a lookup before a socket could be opened, and a lookup can be slow or fail
// for reasons that have nothing to do with which family to use.
//
// The address is parsed with the form that understands an interface name after
// a percent sign, which some IPv6 addresses need to say which network they
// belong to. The older parser rejects those outright, and treating one as a
// name would quietly open the wrong kind of socket.
//
// An IPv4 address written in IPv6 form is IPv4 for this purpose: it is
// delivered as IPv4, and address resolution reduces it to its IPv4 form before
// anything is sent.
func dialsIPv6(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.Is6() && !ip.Is4In6()
}
