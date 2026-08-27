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
	// ErrVhostExists reports that a name is already published and was not
	// replaced. Callers distinguish it from a rejected request because the
	// remedies differ: one means choose another name, the other means fix
	// what was asked for.
	ErrVhostExists = errors.New("router: a service is already published under that name")
	// ErrVhostRejected reports that the request itself was not acceptable —
	// a name that is not a hostname, a wildcard, or a port outside the
	// usable range.
	ErrVhostRejected = errors.New("router: the name or port was refused")
	// ErrVhostAbsent reports that a name asked to be withdrawn is not
	// published. Distinct from the refusal below because the remedies differ:
	// one means there is nothing to do, the other means the name belongs to
	// somebody else.
	ErrVhostAbsent = errors.New("router: that name is not published")
	// ErrVhostImmutable reports that a name exists but was not published over
	// the control plane, so a caller there may not take it away. It is kept
	// separate from an authorization failure on purpose: no permission an
	// operator could grant makes their own configuration remotely removable, so
	// telling a caller to ask for permission would send them to change a setting
	// that cannot help.
	ErrVhostImmutable = errors.New("router: that name was not published over this connection")
	// ErrVhostLimit reports that the table already holds as many names as it
	// will. It is kept apart from a name that is taken and from a request that
	// was malformed, because the remedy differs: nothing about the request was
	// wrong and choosing another name will not help — something has to be
	// withdrawn first, or whoever runs the agent has to restart it.
	ErrVhostLimit = errors.New("router: this agent holds as many published names as it will")
)

// Provenance records where a route table entry came from. It answers "who
// put this here", which is a different question from "what is this name" —
// an operator override of the compiled-in "ssh" name is still an
// operator-supplied entry, because the operator, not the compiled-in
// default, is what put that address there.
//
// It is a string rather than a number because it is rendered for people and
// carried to other programs, where a self-describing word survives being
// read out of context and a number does not. Treat the set as open: a
// reader that does not recognize a value must not assume there are only
// three, the same way every other open set in this tree is handled.
type Provenance string

const (
	// ProvenanceBuiltin is a compiled-in default that nothing overrode.
	ProvenanceBuiltin Provenance = "builtin"
	// ProvenanceConfig was supplied by the operator, whether through the
	// configuration file or a command-line flag.
	ProvenanceConfig Provenance = "config"
	// ProvenanceRuntime was added while the process was running, over the
	// control plane, and disappears when the process restarts. Only an
	// entry with this provenance may be removed by a remote caller.
	ProvenanceRuntime Provenance = "runtime"
)

type route struct {
	raw     string
	network string
	address string
	// prov records where this entry came from — config, builtin, or
	// runtime — not who created it. Removal safety rests on origin alone:
	// an entry the operator configured cannot be withdrawn over the
	// network, while a runtime-published one can be, by any authorized
	// caller, not only the one that published it. Provenance carries no
	// caller identity, so the table has no way to tell one authorized
	// caller's entry apart from another's; distinguishing them would need
	// a field this type does not have.
	prov Provenance
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
	// merged carries every route's address; prov carries where that address
	// came from. The two are built together (defaults seeded as compiled-in,
	// then every override — even one that repeats a default's own name —
	// marked as operator-supplied) so nothing after this point has to infer
	// provenance from anything but this one map.
	merged := map[string]string{"ssh": defaultSSHAddr, "docker": defaultDockerAddr}
	prov := map[string]Provenance{"ssh": ProvenanceBuiltin, "docker": ProvenanceBuiltin}
	for name, addr := range overrides {
		merged[name] = addr
		prov[name] = ProvenanceConfig
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
		routes[name] = route{raw: raw, network: network, address: address, prov: prov[name]}
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

// AddVhost publishes a hostname pointing at a port on this machine's loopback
// interface, for as long as this process runs. The name table is rebuilt from
// configuration at every start, so nothing added here survives a restart.
//
// The caller supplies a port and never an address. The address is composed
// here, so no caller can name a destination of its own choosing: a route table
// that could be pointed anywhere on request would not be deciding where
// traffic may go, it would be taking suggestions.
//
// Everything is checked before anything is stored. The table has never been
// able to contain an entry that was not usable, and every reader depends on
// that; letting one in would mean a name that resolves at lookup time and only
// then turns out to go nowhere.
func (r *Router) AddVhost(host string, port int) error {
	// A star would claim every name nobody has claimed yet underneath it,
	// including names this agent's operator has not chosen yet and may want to
	// configure later — and a configured name cannot displace one already
	// published, so they would find their own name shadowed by a caller's
	// pattern, at a port the caller picked. Publishing one name is what this is
	// for.
	if strings.HasPrefix(host, "*") {
		return fmt.Errorf("%w: %q covers more than one name; publish a single name",
			ErrVhostRejected, host)
	}
	if err := ValidateVhostKey(host); err != nil {
		return fmt.Errorf("%w: %v", ErrVhostRejected, err)
	}
	// Ports are checked here rather than left to the address parser, which
	// only looks at the shape of what it is given: a number far outside the
	// usable range reads as a valid address and fails much later, when
	// somebody tries the name and the dial is refused for a reason that no
	// longer points at the request that caused it.
	//
	// Zero is refused rather than read as "pick one for me". Nothing here
	// picks ports, so accepting it would only let a mistyped port look like a
	// deliberate request for something this cannot do.
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port %d is outside the usable range 1-65535", ErrVhostRejected, port)
	}
	raw := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	network, address, err := parseAddr(raw)
	if err != nil {
		// Unreachable while the port is range-checked above, which is the
		// point: the parser stays the single place that decides what an
		// address means, so this cannot drift into accepting something the
		// rest of the table would reject.
		return fmt.Errorf("%w: %v", ErrVhostRejected, err)
	}
	if r.vhosts == nil {
		return fmt.Errorf("%w: this agent does not serve names", ErrVhostRejected)
	}
	return r.vhosts.add(host, route{
		raw: raw, network: network, address: address,
		prov: ProvenanceRuntime,
	})
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
	// Builtin is derived from Provenance and reports only whether this
	// entry is still a compiled-in default. It is kept because other
	// programs already read it; Provenance is the authoritative answer,
	// because it can also distinguish an operator-supplied entry from one
	// added while the process was running, which Builtin cannot.
	Builtin bool
	// Provenance says where the entry came from. Readers should treat the
	// set of values as open and not assume the three they know are all
	// there will ever be.
	Provenance Provenance
}

// RemoveVhost withdraws a name that was published while this agent was running.
//
// It reports the pattern that resumes serving the name when one covers it, and
// the address that pattern points at, so a caller is never told a name was
// withdrawn while it still answers, and never told it still answers without
// being told where. The two are empty together. Only a name published over the
// control plane may be withdrawn; anything from the operator's configuration is
// refused, naming what is in the way.
func (r *Router) RemoveVhost(host string) (shadowedBy, shadowedByAddress string, err error) {
	if r.vhosts == nil {
		return "", "", fmt.Errorf("%w: %q is not published here", ErrVhostAbsent, host)
	}
	// Validated on the way in for the same reason a publish is: a name that
	// could never have been published cannot be present, and saying so as a
	// rejected request is more use than reporting it as merely absent.
	if err := ValidateVhostKey(host); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrVhostRejected, err)
	}
	return r.vhosts.remove(host)
}

// VhostDetail is one published name, with where it came from and where it
// points. It mirrors RouteDetail because the two answer the same question about
// different namespaces, and a reader of one should not have to learn a second
// shape to read the other.
type VhostDetail struct {
	// Name is the whole hostname. A pattern is rendered with its star, as the
	// operator wrote it.
	Name string
	// Address is the destination as configured, in the form it was given.
	Address string
	// Builtin is derived from Provenance, for symmetry with a route. No
	// published name is compiled in today, so this is always false — the
	// distinction that matters here is between the operator's configuration and
	// something added while the agent was running, which Provenance carries.
	Builtin bool
	// Provenance says where the entry came from. Readers should treat the set of
	// values as open rather than assuming the ones they know are all there will
	// ever be.
	Provenance Provenance
}

// VhostDetails returns every name this agent publishes, sorted by name.
//
// Until this existed a published name was disclosed by nothing: the table could
// be added to over the control plane and read by no one, so the agent's own log
// was the only record and it went away when the process did.
func (r *Router) VhostDetails() []VhostDetail {
	if r.vhosts == nil {
		return nil
	}
	out := r.vhosts.details()
	for i := range out {
		out[i].Builtin = out[i].Provenance == ProvenanceBuiltin
	}
	return out
}

// RouteDetails returns every route's name, configured address, and
// provenance, sorted by name so the result is deterministic regardless of
// the route table's internal map order.
//
// Provenance answers where the entry came from, and Builtin is derived from
// it: overriding the compiled-in "ssh" name with a custom address reports
// config provenance and a false Builtin, because an operator, not the
// compiled-in default, is what put that address there. The two fields can
// never disagree, because one is computed from the other here.
func (r *Router) RouteDetails() []RouteDetail {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RouteDetail, 0, len(r.routes))
	for name, rt := range r.routes {
		out = append(out, RouteDetail{
			Name:       name,
			Address:    rt.raw,
			Builtin:    rt.prov == ProvenanceBuiltin,
			Provenance: rt.prov,
		})
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
