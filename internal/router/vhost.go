package router

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mauriciomem/quic-link/internal/names"
)

// vhostLabel reports whether one part of a hostname key is a legal label. It is
// deliberately not the same rule as a route name: a route name is a short token
// chosen by an operator and may contain characters a hostname may not, while
// these keys are hostnames and have to look like one.
//
// The rule itself is not restated here. It is asked of the code that serves
// these names, so a key accepted here cannot be one that is refused when a
// request for it arrives.
func vhostLabel(s string) bool { return names.ValidLabel(s) }

// ValidateVhostLabel checks one part of a hostname — the piece a caller names a
// service by, before the server and suffix are appended to it.
//
// It shares the rule below rather than restating it, so a label accepted here
// cannot be one the whole-name check would go on to reject. A star is refused
// outright: a single label is a single name, and one that could stand for
// several is not what a caller asking for one service means.
func ValidateVhostLabel(label string) error {
	if label == "" {
		return fmt.Errorf("a service name must not be empty")
	}
	if strings.Contains(label, ".") {
		return fmt.Errorf("service name %q must be a single label, with no dots", label)
	}
	if strings.Contains(label, "*") {
		return fmt.Errorf("service name %q must name one service, not a pattern", label)
	}
	if label != strings.ToLower(label) {
		return fmt.Errorf("service name %q must be lowercase; hostnames are compared without regard to case", label)
	}
	if !vhostLabel(label) {
		return fmt.Errorf("service name %q is not usable in a hostname: use letters, digits and dashes, "+
			"starting and ending with a letter or digit", label)
	}
	return nil
}

// ValidateVhostKey checks a hostname key for the vhost table.
//
// A key is either a hostname, or a hostname with its first label replaced by a
// star meaning "any single label here". The star is only ever a whole label and
// only ever the first one: a pattern that could match part of a label would
// match `evil-grafana.internal` when it meant `grafana.internal`, which is the
// kind of over-reach that is invisible until it matters.
func ValidateVhostKey(key string) error {
	if key == "" {
		return fmt.Errorf("vhost name must not be empty")
	}
	if key != strings.ToLower(key) {
		return fmt.Errorf("vhost name %q must be lowercase; hostnames are compared without regard to case", key)
	}
	if len(key) > 253 {
		return fmt.Errorf("vhost name %q is longer than a hostname may be", key)
	}
	labels := strings.Split(key, ".")
	if labels[0] == "*" && len(labels) == 1 {
		return fmt.Errorf("vhost name %q would match everything; name at least one label after the star", key)
	}
	for i, l := range labels {
		if l == "*" {
			if i != 0 {
				return fmt.Errorf("vhost name %q may only use a star as its first label", key)
			}
			continue
		}
		if strings.Contains(l, "*") {
			return fmt.Errorf("vhost name %q may only use a star as a whole label, never part of one", key)
		}
		if !vhostLabel(l) {
			return fmt.Errorf("vhost name %q is not a hostname: %q is not a valid label", key, l)
		}
	}
	return nil
}

// describe names a provenance the way a refusal message should say it out
// loud, so a caller told "no" learns which kind of entry is in the way and
// therefore what to do about it.
func (p Provenance) describe() string {
	switch p {
	case ProvenanceBuiltin:
		return "a compiled-in default"
	case ProvenanceConfig:
		return "set in the agent's configuration"
	case ProvenanceRuntime:
		return "published while the agent was running"
	default:
		return "of an unrecognized origin"
	}
}

// vhosts resolves a hostname to a local address.
//
// mu guards both maps. They are read on every request that arrives by name,
// which is the busiest path here, and written only when someone publishes a
// name while the process runs — so readers share the lock and a writer
// briefly excludes them. Reading a Go map while another goroutine writes it
// is not a subtle problem: it stops the process outright, mid-request, and
// cannot be recovered from.
//
// The pointer to this value is set once when the table is built and never
// replaced; entries are changed inside it. Anything that swapped the pointer
// instead would put the swap itself outside this lock.
type vhosts struct {
	mu       sync.RWMutex
	exact    map[string]route
	wildcard map[string]route // keyed on what follows the star
}

// MaxVhosts bounds how many names one agent holds at once, counting both the
// ones its operator configured and the ones published while it was running.
//
// It is exported so the configuration validator can refuse an over-large file
// with the same number this table enforces, rather than keeping a second copy
// that could drift away from it.
//
// Without a bound a caller allowed to publish can publish without end:
// authentication decides who may ask, and nothing decided how often. The table
// grows for as long as the process lives, and every entry also enlarges the
// reply that lists it — so a large enough table stops being readable, which
// disables the surface that would have shown what was happening.
//
// The number comes from that reply rather than from memory, which is the
// weaker worry: tens of thousands of entries are only a few megabytes. Encoded
// as JSON for the local socket a worst-case entry — the longest hostname a name
// is allowed to have — costs about 338 bytes against a budget of roughly 65000,
// so the listing stops fitting somewhere above 192 entries. Half of that leaves
// room for an entry to grow by half again before the listing is at risk, which
// matters because the shape is allowed to gain fields. It is also several times
// more names than observed use: a two-machine test published 28.
const MaxVhosts = 128

func newVhosts(entries map[string]string) (*vhosts, error) {
	// Refused at startup rather than at the first publish, which is the same
	// posture this function already takes towards an address it cannot parse:
	// a configuration that cannot be served should stop the process while an
	// operator is watching, not surprise the first caller.
	//
	// Defense in depth: the configuration validator is expected to catch an
	// over-large set first, and it does so where the operator gets the exit
	// code that means "fix your configuration". This check stays because the
	// table itself must never silently accept more names than it will serve,
	// whatever call site built the set — and it is the only guard for a call
	// site that never passed through that validator.
	if len(entries) > MaxVhosts {
		return nil, fmt.Errorf("%w: %d names are configured and this build holds at most %d",
			ErrVhostLimit, len(entries), MaxVhosts)
	}
	v := &vhosts{
		exact:    make(map[string]route, len(entries)),
		wildcard: make(map[string]route),
	}
	for key, raw := range entries {
		if err := ValidateVhostKey(key); err != nil {
			return nil, err
		}
		network, address, err := parseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("vhost %q: %w", key, err)
		}
		// A vhost built here came from the operator's configuration. Saying
		// so explicitly keeps every entry's provenance a set value rather
		// than a zero value that means nothing in particular.
		r := route{raw: raw, network: network, address: address, prov: ProvenanceConfig}
		if rest, ok := strings.CutPrefix(key, "*."); ok {
			v.wildcard[rest] = r
			continue
		}
		v.exact[key] = r
	}
	return v, nil
}

// add publishes one already-validated entry.
//
// It refuses to displace anything already there. Repeating a request that has
// already been carried out is not a refusal though: if the name is present, was
// published this same way, and points at the same place, the caller asked for a
// state that already holds, so it is told yes and nothing changes.
//
// That makes publishing safe to retry, which is what a caller needs when a
// request may have succeeded without its reply arriving. Such a call is bounded
// by a short deadline and the connection can drop inside it, so a caller cannot
// always tell a lost reply from a request that never ran. Retrying must not turn
// a success into an error.
//
// Anything else is refused and says which kind of entry is in the way: a
// caller must not be able to take over a name the operator configured, or one
// another caller published, by asking for it a second time.
//
// A table that already holds as many names as it will is also refused, and the
// refusal names no name and no number: it travels back to whoever asked, and
// what this build happens to hold is not their business. The repeat above is
// deliberately not subject to it, because a request that adds no entry cannot
// be the one that made the table too large.
func (v *vhosts) add(key string, r route) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.exact[key]; ok {
		if existing.prov == ProvenanceRuntime && existing.raw == r.raw {
			return nil
		}
		return fmt.Errorf("%w: %q is %s and points at %s",
			ErrVhostExists, key, existing.prov.describe(), existing.raw)
	}
	// Asked after the repeat above, deliberately: repeating a request that
	// already holds adds no entry, so a full table must not turn a success
	// into a refusal. Both maps count, because both are served from here and
	// both appear in the listing.
	if len(v.exact)+len(v.wildcard) >= MaxVhosts {
		return fmt.Errorf("%w", ErrVhostLimit)
	}
	v.exact[key] = r
	return nil
}

// remove withdraws a name that was published while the agent was running, and
// reports the pattern that takes over serving it, if one does.
//
// The check and the deletion happen under one lock. Reading the entry, deciding
// it is safe to remove, releasing, and then deleting would leave a window in
// which what was checked is not what is deleted.
//
// Only a name published this way may be withdrawn. One from the operator's
// configuration is theirs, and a caller that could take it away over the network
// could silently stop serving something the operator set up. The refusal says
// which kind is in the way rather than only that it refused.
//
// The last two return values are the reason a withdrawal can be true and still
// not leave the name unanswered: a pattern in the configuration may cover it,
// and with the exact entry gone that pattern resumes serving the name, at
// whatever address it points to. Saying so is the difference between reporting
// what happened and implying something that did not.
func (v *vhosts) remove(key string) (shadowedBy string, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	existing, ok := v.exact[key]
	if !ok {
		return "", fmt.Errorf("%w: %q is not published here", ErrVhostAbsent, key)
	}
	if existing.prov != ProvenanceRuntime {
		return "", fmt.Errorf("%w: %q is %s and points at %s",
			ErrVhostImmutable, key, existing.prov.describe(), existing.raw)
	}
	delete(v.exact, key)

	// Ask the same question a request would ask, now that the entry is gone.
	// A pattern answering here means the name still resolves.
	rest := key
	for {
		i := strings.Index(rest, ".")
		if i < 0 {
			return "", nil
		}
		rest = rest[i+1:]
		if rest == "" {
			return "", nil
		}
		if _, covered := v.wildcard[rest]; covered {
			return "*." + rest, nil
		}
	}
}

// resolve finds the entry for a hostname: an exact name first, then the most
// specific star pattern that covers it.
//
// The search walks the name one label at a time and looks each remainder up
// directly, so the first pattern found is necessarily the longest one that
// matches, and nothing depends on the order a map happens to be stored in.
// Asking each pattern in turn whether it matched would give a different answer
// on different runs whenever two patterns both applied.
func (v *vhosts) resolve(host string) (route, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if r, ok := v.exact[host]; ok {
		return r, true
	}
	rest := host
	for {
		i := strings.Index(rest, ".")
		if i < 0 {
			return route{}, false
		}
		rest = rest[i+1:]
		if rest == "" {
			return route{}, false
		}
		if r, ok := v.wildcard[rest]; ok {
			return r, true
		}
	}
}

// names returns every published hostname, for logging and diagnosis.
//
// details reports every published name with where it came from and where it
// points, sorted so the answer does not depend on map ordering.
//
// A pattern entry is rendered with the star it was configured with, because
// that is the name an operator wrote and the one they will look for. The
// address is the raw form the entry was built from rather than a reassembled
// one, so what is reported is what was configured.
//
// It reads under the same lock as a lookup does, for the same reason names()
// does: what matters is that a write may be happening, not how often this runs.
func (v *vhosts) details() []VhostDetail {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]VhostDetail, 0, len(v.exact)+len(v.wildcard))
	for k, r := range v.exact {
		out = append(out, VhostDetail{Name: k, Address: r.raw, Provenance: r.prov})
	}
	for k, r := range v.wildcard {
		out = append(out, VhostDetail{Name: "*." + k, Address: r.raw, Provenance: r.prov})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// It reads under the same lock as a lookup does. It is called far less often,
// but a reader that skipped the lock would be exactly as unsafe as a busy one:
// what matters is that a write may be happening, not how often this runs.
func (v *vhosts) names() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.exact)+len(v.wildcard))
	for k := range v.exact {
		out = append(out, k)
	}
	for k := range v.wildcard {
		out = append(out, "*."+k)
	}
	return out
}
