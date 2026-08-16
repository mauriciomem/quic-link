package config

import (
	"fmt"
	"net"
	"strings"
)

// DialableAddr reports why an address could never be dialled, or nil when it
// might work.
//
// It answers only the question that has a permanent answer: whether this
// program could send a single packet to that address, no matter how the network
// changed around it. An address with no port, or one in a family the outgoing
// socket cannot carry, is wrong in a way that waiting will not fix.
//
// Everything that merely happens to be failing right now is deliberately not
// its business — a name that does not resolve yet, a host that is switched off,
// a port nothing is listening on. Those are worth retrying, and a program that
// refuses to start because of them turns a short outage into one that needs a
// person. Whether such an address is *currently* reachable is a question about
// this instant, and this function does not ask it: it performs no name lookup
// and touches no network.
func DialableAddr(label, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("server %q: cannot dial %q: an address needs a host and a port (%v). "+
			"Nothing about the network can make this work: %w", label, addr, err, ErrInvalid)
	}
	if host == "" {
		return fmt.Errorf("server %q: cannot dial %q: no host to connect to, only a port: %w",
			label, addr, ErrInvalid)
	}

	// An address carrying an interface name is always IPv6: the notation exists
	// only for addresses whose meaning depends on which interface they are used
	// on, and no IPv4 address is written that way. It is separated out because
	// the parser below does not accept the interface suffix and would otherwise
	// mistake the whole thing for a hostname.
	if strings.ContainsRune(host, '%') {
		return fmt.Errorf("server %q: cannot dial %q: outgoing connections carry IPv4 only, "+
			"so this address can never be reached from here: %w", label, addr, ErrInvalid)
	}

	// A literal address states its family outright, so it can be judged here.
	// A name cannot: the addresses behind it are decided elsewhere and can
	// change, so it is left to the connection attempt to find out.
	//
	// The nil check is what keeps a name out of this branch. Parsing a name as
	// an address yields nothing, and asking that nothing for its IPv4 form also
	// yields nothing, which would otherwise read as "this is not IPv4" for
	// every hostname there is.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Errorf("server %q: cannot dial %q: outgoing connections carry IPv4 only, "+
			"so this address can never be reached from here: %w", label, addr, ErrInvalid)
	}
	return nil
}
