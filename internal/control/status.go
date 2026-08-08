package control

import (
	"context"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// RouteDetail describes one route table entry as GetStatus discloses it to
// an administrative caller: the route's name, its configured address, and
// whether that address is still the agent's compiled-in default. It mirrors
// internal/router's own RouteDetail field-for-field but is a distinct type —
// this package must not import internal/router (a control-plane RPC and a
// data-plane dial target are two different assets guarded by two different
// boundaries, the same reasoning that keeps this package's Policy signature
// separate from router.Policy's in authz.go) — so whatever supplies route
// data converts into this type at whichever package already imports both.
type RouteDetail struct {
	Name    string
	Address string
	Builtin bool
}

// RouteSource supplies the current route table for a GetStatus reply. The
// agent's own router satisfies this once the code that opens the control
// stream converts its own route-detail type into this package's RouteDetail.
type RouteSource interface {
	RouteDetails() []RouteDetail
}

// GetStatus reports the agent's build version, when it started serving, and
// its current route table. It carries no authorization logic of its own:
// every unary RPC, this one included, is already gated by the authorize
// interceptor in server.go before it ever reaches here — that is the whole
// point of authorizing at dispatch rather than per-handler. A caller that
// configured no RouteSource gets an empty route list rather than an error;
// an agent with nothing to report is a valid configuration, not a failure.
func (s server) GetStatus(_ context.Context, _ *controlpb.GetStatusRequest) (*controlpb.GetStatusResponse, error) {
	resp := &controlpb.GetStatusResponse{Version: s.version}
	if !s.startedAt.IsZero() {
		resp.StartedUnixMs = s.startedAt.UnixMilli()
	}
	if s.routes == nil {
		return resp, nil
	}
	details := s.routes.RouteDetails()
	resp.Routes = make([]*controlpb.RouteInfo, len(details))
	for i, d := range details {
		resp.Routes[i] = &controlpb.RouteInfo{
			Target:  d.Name,
			Address: d.Address,
			Builtin: d.Builtin,
		}
	}
	return resp, nil
}
