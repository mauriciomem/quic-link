package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

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
}

// Router resolves logical targets to addresses and authorizes each dial. It is
// the sole resolution and authorization boundary on the agent.
type Router struct {
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
	merged := map[string]string{"ssh": defaultSSHAddr, "docker": defaultDockerAddr}
	for name, addr := range overrides {
		merged[name] = addr
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
		routes[name] = route{raw: raw, network: network, address: address}
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

// resolve picks the entry a header refers to.
func (r *Router) resolve(h proto.Header) (route, bool) {
	if h.Kind == proto.KindHTTP {
		if r.vhosts == nil {
			return route{}, false
		}
		return r.vhosts.resolve(h.Host)
	}
	rt, ok := r.routes[h.Target]
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

func (r *Router) Targets() []string {
	names := make([]string, 0, len(r.routes))
	for name := range r.routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
