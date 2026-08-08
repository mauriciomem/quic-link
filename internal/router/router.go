package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/mauriciomem/quic-link/internal/proto"
)

const (
	defaultSSHAddr    = "tcp://127.0.0.1:22"
	defaultDockerAddr = "unix:///var/run/docker.sock"
)

var (
	ErrUnknownTarget = errors.New("router: unknown target")
	ErrUnauthorized  = errors.New("router: unauthorized")
)

type route struct {
	raw     string
	network string
	address string
	// builtin is true only for the two compiled-in defaults that New seeds
	// the route table with, and only if nothing overrode them. It records
	// provenance ("did the operator configure this"), not whether the name
	// happens to be one of the two reserved ones — an operator override of
	// "ssh" clears it, because the operator, not the compiled-in default,
	// is what put that address there.
	builtin bool
}

// Router resolves logical targets to addresses and authorizes each dial. It is
// the sole resolution and authorization boundary on the agent.
type Router struct {
	// mu guards routes, including the read inside resolve() that Dial calls
	// on every stream. There is no mutator yet — routes is built once in
	// New/NewWithVhosts and never written again after that, so today's
	// concurrent reads are race-free without it. The lock is added ahead of
	// need so a future route-table mutation lands on already-locked readers
	// instead of requiring every reader to be revisited a second time.
	mu     sync.RWMutex
	routes map[string]route
	vhosts *vhosts
	policy Policy
	dialer net.Dialer
}

// New builds a Router from built-ins overlaid with overrides, using policy
// (nil => AllowAll). Every address is parsed up front, so a bad address fails
// at startup, not at dial time.
func New(overrides map[string]string, policy Policy) (*Router, error) {
	return NewWithVhosts(overrides, nil, policy)
}

// NewWithVhosts builds a Router that also answers for hostnames. A stream that
// names a host is resolved against the vhost table; a stream that names a
// target is resolved against the route table. They are separate tables because
// they are separate namespaces: one is a short logical name an operator chose,
// the other is a hostname a browser was told to ask for.
func NewWithVhosts(overrides map[string]string, hosts map[string]string, policy Policy) (*Router, error) {
	if policy == nil {
		policy = AllowAll{}
	}
	// merged carries every route's address; builtin carries whether that
	// address is still the compiled-in default. The two are built together
	// (default seeded true, then every override — even one that repeats the
	// default's own name — flips its entry to false) so nothing after this
	// point has to infer provenance from anything but this one map.
	merged := map[string]string{"ssh": defaultSSHAddr, "docker": defaultDockerAddr}
	builtin := map[string]bool{"ssh": true, "docker": true}
	for name, addr := range overrides {
		merged[name] = addr
		builtin[name] = false
	}
	routes := make(map[string]route, len(merged))
	for name, raw := range merged {
		// Defense in depth: the --route flag parser and the config
		// validators are expected to catch a bad name first, but the
		// route table itself must never silently accept one that slipped
		// through some other call site.
		if err := ValidateRouteName(name); err != nil {
			return nil, fmt.Errorf("route %q: %w", name, err)
		}
		network, address, err := parseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", name, err)
		}
		routes[name] = route{raw: raw, network: network, address: address, builtin: builtin[name]}
	}
	// Addresses are parsed here rather than at dial time so a mistake in the
	// configuration is a startup failure the operator sees, not a failure that
	// waits for the first person to try the name.
	vh, err := newVhosts(hosts)
	if err != nil {
		return nil, err
	}
	return &Router{routes: routes, vhosts: vh, policy: policy}, nil
}

// Dial resolves the stream's destination, authorizes (peer, h), and dials.
// Errors: ErrUnknownTarget (->1), ErrUnauthorized (->2), or a wrapped dial
// error (->3).
//
// A stream carries either a target or a host, never both, and which one decides
// where it goes. Resolution for both lives here because this is the single
// place allowed to turn something a client said into an address.
func (r *Router) Dial(ctx context.Context, peer Identity, h proto.Header) (net.Conn, error) {
	rt, ok := r.resolve(h)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownTarget, describeDestination(h))
	}
	if err := r.policy.Authorize(peer, h); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	conn, err := r.dialer.DialContext(ctx, rt.network, rt.address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rt.raw, err)
	}
	return conn, nil
}

// resolve picks the entry a header refers to. It is Dial's hottest read —
// called on every data-plane stream — so it takes its own read lock rather
// than relying on a caller to hold one.
func (r *Router) resolve(h proto.Header) (route, bool) {
	if h.Kind == proto.KindHTTP {
		if r.vhosts == nil {
			return route{}, false
		}
		return r.vhosts.resolve(h.Host)
	}
	r.mu.RLock()
	rt, ok := r.routes[h.Target]
	r.mu.RUnlock()
	return rt, ok
}

// describeDestination names what a stream asked for, so a refusal says which
// of the two namespaces was searched and what was looked for in it. A message
// that always blamed a target would be actively misleading for a stream that
// named a host and no target at all.
func describeDestination(h proto.Header) string {
	if h.Kind == proto.KindHTTP {
		return fmt.Sprintf("no service is published as %q", h.Host)
	}
	return fmt.Sprintf("no target %q", h.Target)
}

// Vhosts returns every published hostname, in a stable order.
func (r *Router) Vhosts() []string {
	if r.vhosts == nil {
		return nil
	}
	names := r.vhosts.names()
	sort.Strings(names)
	return names
}

// Targets returns every configured route name, in a stable order.
func (r *Router) Targets() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.routes))
	for name := range r.routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RouteDetail describes one entry in the route table for an administrative
// reader (e.g. a status query): its name, the address string it was
// configured with, and whether that address is still the compiled-in
// default. It is a router-package-local type on purpose — the conversion to
// any wire-facing representation belongs at whatever boundary later needs it,
// not here.
type RouteDetail struct {
	Name    string
	Address string
	Builtin bool
}

// RouteDetails returns every route's name, configured address, and
// provenance, sorted by name so the result is deterministic regardless of
// the route table's internal map order.
//
// Builtin answers "did the operator configure this entry, or is it a
// compiled-in default nobody touched" — not "is this name one of the two
// reserved ones". Overriding the built-in "ssh" name with a custom address
// makes that entry's Builtin false, because an operator, not the compiled-in
// default, is what put that address there.
func (r *Router) RouteDetails() []RouteDetail {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RouteDetail, 0, len(r.routes))
	for name, rt := range r.routes {
		out = append(out, RouteDetail{Name: name, Address: rt.raw, Builtin: rt.builtin})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parseAddr converts a route address to a (network, address) pair for net.Dial.
func parseAddr(raw string) (network, address string, err error) {
	switch {
	case strings.HasPrefix(raw, "tcp://"):
		hostport := strings.TrimPrefix(raw, "tcp://")
		if _, _, err := net.SplitHostPort(hostport); err != nil {
			return "", "", fmt.Errorf("invalid tcp address %q: %w", raw, err)
		}
		return "tcp", hostport, nil
	case strings.HasPrefix(raw, "unix://"):
		path := strings.TrimPrefix(raw, "unix://")
		if !strings.HasPrefix(path, "/") {
			return "", "", fmt.Errorf("unix address must be an absolute path (unix:///path): %q", raw)
		}
		return "unix", path, nil
	default:
		return "", "", fmt.Errorf("unsupported address scheme %q (want tcp:// or unix://)", raw)
	}
}
