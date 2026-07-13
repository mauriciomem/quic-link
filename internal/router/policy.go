package router

import "github.com/mauriciomem/quic-link/internal/proto"

// Policy decides whether a peer may open a stream for a target.
// nil = allow; non-nil = deny (surfaced as status 2).
type Policy interface {
	Authorize(peer Identity, h proto.Header) error
}

// AllowAll authorizes every authenticated peer for every target — the working
// default while per-key ACLs stay an open question. The check-point is
// mandatory even though it always allows, so adding real policy later is a
// swap of this value, not new plumbing.
type AllowAll struct{}

func (AllowAll) Authorize(Identity, proto.Header) error { return nil }

// PolicyFunc adapts a function to Policy (used to inject test policies).
type PolicyFunc func(peer Identity, h proto.Header) error

func (f PolicyFunc) Authorize(peer Identity, h proto.Header) error { return f(peer, h) }
