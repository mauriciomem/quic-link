package router

import (
	"fmt"
	"regexp"
	"strings"
)

// vhostLabel is one part of a hostname key. It is deliberately not the same
// rule as a route name: a route name is a short token chosen by an operator and
// may contain characters a hostname may not, while these keys are hostnames and
// have to look like one.
var vhostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

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
		if !vhostLabel.MatchString(l) {
			return fmt.Errorf("vhost name %q is not a hostname: %q is not a valid label", key, l)
		}
	}
	return nil
}

// vhosts resolves a hostname to a local address.
type vhosts struct {
	exact    map[string]route
	wildcard map[string]route // keyed on what follows the star
}

func newVhosts(entries map[string]string) (*vhosts, error) {
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

// resolve finds the entry for a hostname: an exact name first, then the most
// specific star pattern that covers it.
//
// The search walks the name one label at a time and looks each remainder up
// directly, so the first pattern found is necessarily the longest one that
// matches, and nothing depends on the order a map happens to be stored in.
// Asking each pattern in turn whether it matched would give a different answer
// on different runs whenever two patterns both applied.
func (v *vhosts) resolve(host string) (route, bool) {
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

// names returns every configured hostname, for logging and diagnosis.
func (v *vhosts) names() []string {
	out := make([]string, 0, len(v.exact)+len(v.wildcard))
	for k := range v.exact {
		out = append(out, k)
	}
	for k := range v.wildcard {
		out = append(out, "*."+k)
	}
	return out
}
