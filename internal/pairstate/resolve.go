package pairstate

import (
	"errors"
	"fmt"
	"sort"

	"github.com/mauriciomem/quic-link/internal/config"
)

var ErrPinConflict = errors.New("pairstate: server pin differs between config and paired.toml")

// EffectiveAuthorized returns the set of client pins an agent accepts. A
// non-empty flag list replaces both the config list and the file; otherwise
// the result is the config list together with every file entry, whatever its
// state.
func EffectiveAuthorized(cfgList, flagList []string, fileEntries []Entry) map[string]struct{} {
	set := make(map[string]struct{})
	if len(flagList) > 0 {
		for _, p := range flagList {
			set[p] = struct{}{}
		}
		return set
	}
	for _, p := range cfgList {
		set[p] = struct{}{}
	}
	for p := range Allowed(LoadResult{Entries: fileEntries}) {
		set[p] = struct{}{}
	}
	return set
}

// ResolveServers merges the servers of config.toml with those of paired.toml
// into a new map; neither input is modified. A server only in paired.toml
// becomes config.Server{Addr, Pin}. A server in both keeps its config entry,
// with the paired pin filling an empty config pin and the paired addr used
// only when config sets neither addr nor listen. The
// two sources naming different pins for one server is an error matching both
// ErrPinConflict and config.ErrInvalid, since silently trusting either would
// hide a re-keyed or impersonated server. Each paired entry is re-validated
// as LoadPaired validates it, and the first invalid one is an error matching
// config.ErrInvalid. It takes no flag input.
func ResolveServers(cfg map[string]config.Server, paired map[string]PairedServer) (map[string]config.Server, error) {
	out := make(map[string]config.Server, len(cfg)+len(paired))
	for name, s := range cfg {
		out[name] = s
	}
	names := make([]string, 0, len(paired))
	for name := range paired {
		names = append(names, name)
	}
	sort.Strings(names) // report the same conflict on every run
	for _, name := range names {
		p := paired[name]
		if err := validatePaired(name, p.Addr, p.Pin); err != nil {
			return nil, fmt.Errorf("%w: paired.toml entry: %v", config.ErrInvalid, err)
		}
		s, inConfig := out[name]
		if !inConfig {
			out[name] = config.Server{Addr: p.Addr, Pin: p.Pin}
			continue
		}
		if s.Pin != "" && s.Pin != p.Pin {
			return nil, fmt.Errorf("%w: %w: server %q has pin %s in config but %s in paired.toml; "+
				"re-join the server to replace the paired pin, or run \"quic-link server forget %s\" "+
				"to keep the config pin", config.ErrInvalid, ErrPinConflict, name, s.Pin, p.Pin, name)
		}
		if s.Addr == "" && s.Listen == "" { // config's addr or listen wins
			s.Addr = p.Addr
		}
		s.Pin = p.Pin
		out[name] = s
	}
	return out, nil
}
