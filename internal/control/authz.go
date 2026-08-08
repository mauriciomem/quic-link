package control

// PeerIdentity is the authenticated peer's stable credential, as understood
// by the control plane. It is a package-local mirror of "who is calling" —
// concretely, the base64(SHA-256(SPKI)) pin the pinning handshake already
// establishes — kept separate from the router package's own identity type on
// purpose: the control plane guards a different asset (an administrative
// RPC) than route resolution does (a TCP dial target), and each side of that
// boundary owning its own copy of "who is calling" means neither package has
// to change its identity representation because the other one does.
type PeerIdentity struct {
	Pin string
}

// Short returns the identity's short form for logging: the first 8
// characters of the pin, or the whole pin if it is shorter than that. This
// mirrors the convention every other identity-bearing log line in the tree
// already uses, so a control-plane log line reads the same way a data-plane
// one does.
func (id PeerIdentity) Short() string {
	const n = 8
	if len(id.Pin) < n {
		return id.Pin
	}
	return id.Pin[:n]
}

// Policy decides whether an authenticated peer may invoke a control-plane
// method. nil = allow; non-nil = deny, surfaced to the caller as a gRPC
// PermissionDenied status.
//
// This is deliberately a different shape from the router package's
// authorization policy, which authorizes a data-plane stream against a
// target address. An administrative RPC has no stream header to check
// against — reusing that signature here would mean either fabricating a fake
// one to satisfy the type, or changing the data-plane signature to
// accommodate an administrative caller. Two different boundaries guarding
// two different kinds of asset get two different Policy types on purpose.
type Policy interface {
	Authorize(peer PeerIdentity, method string) error
}

// AllowAll authorizes every authenticated peer for every control-plane
// method. It is the working default: the check-point exists and is
// consulted on every call, but nothing is denied yet. Swapping this value
// for a real policy later needs no other plumbing change.
type AllowAll struct{}

func (AllowAll) Authorize(PeerIdentity, string) error { return nil }

// PolicyFunc adapts a function to Policy, used to inject a deny policy (or
// one that records what it was called with) in tests without writing a
// named type for each case.
type PolicyFunc func(peer PeerIdentity, method string) error

func (f PolicyFunc) Authorize(peer PeerIdentity, method string) error { return f(peer, method) }
