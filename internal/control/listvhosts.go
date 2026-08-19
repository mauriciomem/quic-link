package control

import (
	"context"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// VhostSource supplies the names an agent publishes, for a listing. The agent's
// own router satisfies this once the code that opens the control stream converts
// its own detail type into this package's VhostDetail.
type VhostSource interface {
	VhostDetails() []VhostDetail
}

// VhostDetail is one published name as it crosses the control plane. It carries
// where the name came from, because that is what decides whether a caller may
// later take it back, and what a person needs in order to tell a name they
// configured from one something added while the agent was running.
type VhostDetail struct {
	Name       string
	Address    string
	Builtin    bool
	Provenance string
}

// ListVhosts reports every name this agent publishes.
//
// It reads and changes nothing, so it is allowed for any authenticated peer
// without the agent's operator having to permit anything: asking what a name
// table holds is not the same as adding to it. Like the other read on this
// service it carries no authorization logic of its own — every unary call is
// gated at dispatch before it arrives here.
//
// An agent with no source of names reports an empty list rather than an error.
// Publishing nothing is a valid configuration, not a failure, and a caller
// cannot tell the two apart from an error anyway.
func (s server) ListVhosts(_ context.Context, _ *controlpb.ListVhostsRequest) (*controlpb.ListVhostsResponse, error) {
	resp := &controlpb.ListVhostsResponse{}
	if s.vhosts == nil {
		return resp, nil
	}
	details := s.vhosts.VhostDetails()
	resp.Vhosts = make([]*controlpb.VhostInfo, len(details))
	for i, d := range details {
		resp.Vhosts[i] = &controlpb.VhostInfo{
			Host:       d.Name,
			Address:    d.Address,
			Builtin:    d.Builtin,
			Provenance: d.Provenance,
		}
	}
	return resp, nil
}
