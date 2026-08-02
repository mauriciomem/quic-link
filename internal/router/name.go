package router

import (
	"fmt"
	"regexp"
)

// routeNamePattern is the single rule for what a route name may look like,
// enforced identically no matter where the name comes from.
var routeNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidateRouteName checks that name is a valid route name: non-empty, at
// most 64 bytes, and made up only of letters, digits, dash, underscore, and
// dot.
//
// The rule exists for two reasons. First, the fwd verb splits its argument
// on a colon and the --route flag splits on an equals sign, so a route name
// containing either character would make a command line genuinely
// ambiguous. Second, a route name is not just a local label: it is written
// into a stream header, resolved against the agent's route table, and
// included in structured log output, so it needs to be a predictable token
// rather than an arbitrary string.
//
// This function is exported and must be called from every place a route
// name is accepted (the --route flag, the config file's [agent.routes]
// table, and the router's own construction) so a bad name is rejected the
// same way regardless of source.
func ValidateRouteName(name string) error {
	if routeNamePattern.MatchString(name) {
		return nil
	}
	if name == "" {
		return fmt.Errorf("route name must not be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("route name %q exceeds 64 bytes", name)
	}
	return fmt.Errorf("route name %q must contain only letters, digits, dash, underscore, and dot", name)
}
