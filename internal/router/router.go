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
	policy Policy
	dialer net.Dialer
}

// New builds a Router from built-ins overlaid with overrides, using policy
// (nil => AllowAll). Every address is parsed up front, so a bad address fails
// at startup, not at dial time.
func New(overrides map[string]string, policy Policy) (*Router, error) {
	if policy == nil {
		policy = AllowAll{}
	}
	merged := map[string]string{"ssh": defaultSSHAddr, "docker": defaultDockerAddr}
	for name, addr := range overrides {
		merged[name] = addr
	}
	routes := make(map[string]route, len(merged))
	for name, raw := range merged {
		network, address, err := parseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", name, err)
		}
		routes[name] = route{raw: raw, network: network, address: address}
	}
	return &Router{routes: routes, policy: policy}, nil
}

// Dial resolves h.Target, authorizes (peer, h), and dials. Errors:
// ErrUnknownTarget (->1), ErrUnauthorized (->2), or a wrapped dial error (->3).
func (r *Router) Dial(ctx context.Context, peer Identity, h proto.Header) (net.Conn, error) {
	rt, ok := r.routes[h.Target]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTarget, h.Target)
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
