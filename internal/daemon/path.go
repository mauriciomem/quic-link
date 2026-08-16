package daemon

import (
	"net"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// The words status uses to say how a live session is reaching its peer.
//
// Only these two are ever reported. Four more are named in the published
// contract — a mapping asked of a router, a hole punched through one, a proxied
// bound port, and a relay — because fixing the whole vocabulary before anything
// depends on it is cheaper than adding words to a shape consumers already read.
// None of that is built, and a word is never reported before the thing it names
// works: a document claiming a session was relayed when nothing relayed it
// would be worse than one that said nothing at all.
const (
	pathIPv4Direct = "ipv4-direct"
	pathIPv6Direct = "ipv6-direct"
)

// pathOf says how a live connection is reaching its peer, or nothing when that
// cannot be answered.
//
// It asks the connection rather than the socket. A socket that accepts both
// address families reports only that it accepts both, so for a session the far
// end opened it cannot say which family was used; the connection can, because
// the address arrived with the packet that started it.
//
// A connection that cannot report an address at all yields nothing, and so does
// the absence of a connection. Both mean the same thing here — there is nothing
// true to say — and saying nothing is the honest rendering of that.
func pathOf(conn Conn) string {
	if conn == nil {
		return ""
	}
	rap, ok := conn.(transport.RemoteAddrProvider)
	if !ok {
		return ""
	}
	return pathForAddr(rap.RemoteAddr())
}

// pathForAddr names the family of a peer address.
//
// An address arriving on a socket that accepts both families is presented in
// its wider form even when the peer used IPv4, so the question is whether the
// address has an IPv4 form, not how many bytes it is stored in.
func pathForAddr(addr net.Addr) string {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return ""
	}
	if ua.IP.To4() != nil {
		return pathIPv4Direct
	}
	return pathIPv6Direct
}
