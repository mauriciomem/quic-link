package config

import (
	"fmt"
	"net"
)

// DialableAddr reports why an address could never be dialled, or nil when it
// might work.
//
// It answers only the question that has a permanent answer: whether this
// program could send a single packet to that address, no matter how the network
// changed around it. An address that is not a host and a port at all is wrong
// in a way that waiting will not fix.
//
// It deliberately says nothing about which address family an address belongs
// to. Both families are dialled, each on its own socket, so a family is no
// longer a reason to refuse anything — and a rule naming one would have to be
// revisited the next time that changed.
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

	return nil
}
