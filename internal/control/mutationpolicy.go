package control

import "fmt"

// MutationPolicy permits reporting always and changing only when the operator
// has said so.
//
// The rule is written the safe way round: the methods that may be called
// without permission are named, and everything else needs it. Naming the
// dangerous ones instead would mean a method added later, by someone who did
// not think to classify it, is permitted by default — and the first time that
// mattered would be the first time it was wrong. This way such a method is
// refused until somebody says otherwise, which is a visible, harmless failure.
type MutationPolicy struct {
	// AllowMutation reflects the operator's decision. The zero value permits
	// nothing beyond reporting, so a policy that was constructed carelessly is
	// still safe.
	AllowMutation bool
}

// readOnlyMethods may be called by any authenticated peer. They report on the
// agent; none of them changes it.
var readOnlyMethods = map[string]bool{
	"Ping":      true,
	"GetStatus": true,
}

// Authorize implements Policy.
func (p MutationPolicy) Authorize(_ PeerIdentity, method string) error {
	if !changesTheAgent(method) {
		return nil
	}
	if p.AllowMutation {
		return nil
	}
	return fmt.Errorf("%s changes what this agent publishes, and remote changes are "+
		"switched off; the agent's operator can allow them", method)
}
