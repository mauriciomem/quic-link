package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// VhostsSnapshot is the JSON-serializable body of a successful names relay: the
// names a server's agent says it is publishing, right now, over the control
// plane.
//
// It is its own shape and carries its own version, for the same reasons the
// route listing does. Plain status is a frozen document every caller reads on
// every call; this one is fetched live only when asked, and can fail in ways
// plain status cannot — the agent may be too old to answer, mid-reconnect, or
// gone. Folding it into that document would make every status call pay for a
// network round trip nobody asked for.
type VhostsSnapshot struct {
	Schema int         `json:"schema"`
	Server string      `json:"server"`
	Vhosts []VhostInfo `json:"vhosts"`
}

// VhostInfo is one published name as it appears in the listing.
type VhostInfo struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	Builtin bool   `json:"builtin"`
	// Provenance says whether the name came from the agent's configuration or
	// was published while it was running. It is the field that decides whether
	// a name could later be taken back, so it is reported rather than inferred.
	Provenance string `json:"provenance"`
}

// vhostsProvider implements ipc.VhostsProvider by relaying a listing call to a
// named server's agent through the session pool, turning each way that relay
// can fail short of success into its own reason. It reuses the route relay's
// state check, because the six situations that stop a live call are the same
// ones whatever is being asked for.
type vhostsProvider struct {
	pool SessionPool
}

// NewVhostsProvider returns an ipc.VhostsProvider that relays published-name
// queries through pool. Exported so a test can drive it against a fake pool
// without standing up the IPC socket.
func NewVhostsProvider(pool SessionPool) ipc.VhostsProvider {
	return &vhostsProvider{pool: pool}
}

// VhostsJSON implements ipc.VhostsProvider.
func (p *vhostsProvider) VhostsJSON(ctx context.Context, server string) ([]byte, error) {
	state, err := p.pool.EntryState(server)
	if err != nil {
		return nil, &ipc.RoutesError{Status: 2, Msg: err.Error()}
	}
	if msg, unavailable := stateUnavailableMessage(server, state); unavailable {
		return nil, &ipc.RoutesError{Status: 3, Msg: msg}
	}

	var resp *controlpb.ListVhostsResponse
	callErr := p.pool.ControlCall(ctx, server, func(cctx context.Context, c *control.Client) error {
		r, lerr := c.ListVhosts(cctx, &controlpb.ListVhostsRequest{})
		if lerr != nil {
			return lerr
		}
		resp = r
		return nil
	})
	if callErr != nil {
		if status.Code(callErr) == codes.Unimplemented {
			// The expected answer from an agent built before this existed, not
			// an exceptional failure. Named distinctly so the remedy is to
			// rebuild both ends rather than to go looking for something else.
			return nil, &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
				"the agent at server %q is running a version that does not report its published names; rebuild both ends", server)}
		}
		// The session looked connected a moment ago and the call did not
		// complete: a mid-call drop, or a displacement by a newer authenticated
		// peer. Both are ordinary textures of a live network call. The real
		// error is kept at debug level so a genuine defect landing here leaves
		// a trace, rather than vanishing behind the operator-facing wording.
		slog.Debug("vhosts: control call failed; reporting as reconnecting",
			"role", "daemon", "session", server, "err", callErr)
		return nil, &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q is reconnecting; try again", server)}
	}

	vhosts := make([]VhostInfo, len(resp.GetVhosts()))
	for i, v := range resp.GetVhosts() {
		vhosts[i] = VhostInfo{
			Host:       v.GetHost(),
			Address:    v.GetAddress(),
			Builtin:    v.GetBuiltin(),
			Provenance: v.GetProvenance(),
		}
	}
	snap := VhostsSnapshot{Schema: 1, Server: server, Vhosts: vhosts}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal vhosts snapshot: %w", err)
	}
	return b, nil
}
