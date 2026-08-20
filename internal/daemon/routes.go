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

// RoutesSnapshot is the JSON-serializable body of a successful routes relay:
// the live route table a named server's agent reported just now, over the
// control plane. It is a deliberately separate shape from StatusSnapshot —
// that one is a frozen contract every caller of plain "status --json" reads
// on every call whether or not routes were asked for; this one is fetched
// live, on its own IPC method, only when asked, and can fail in ways plain
// status never does (the agent might be too old, mid-reconnect, or
// unreachable). Mixing the two would either freeze this one before it is
// ready, or make plain status pay the latency and failure modes of a live
// control-plane call nobody asked it to make.
type RoutesSnapshot struct {
	Schema int         `json:"schema"`
	Server string      `json:"server"`
	Routes []RouteInfo `json:"routes"`
}

// routesProvider implements ipc.RoutesProvider by relaying a GetStatus call
// to a named server's agent through the session pool, and turning every way
// that relay can fail short of success into its own named, distinguishable
// reason. A disabled server, one still connecting, one waiting for its
// agent to call in, one that has permanently failed authentication, an
// agent too old to answer this request at all, and a session that simply
// dropped mid-call are six different situations; an operator (and, later, a
// script reading the process exit code) needs to be able to tell them apart
// without reading logs, not see one interchangeable "not available" string
// standing in for all of them.
type routesProvider struct {
	pool SessionPool
}

// NewRoutesProvider returns an ipc.RoutesProvider that relays route-table
// queries through pool. Exported so a test can drive it directly against a
// fake pool without going through the full IPC socket — the same reason
// NewStatusProvider lets a test drive the status snapshot directly.
func NewRoutesProvider(pool SessionPool) ipc.RoutesProvider {
	return &routesProvider{pool: pool}
}

// stateUnavailableMessage names why no live control client exists for
// server right now, for every state ControlCall itself would refuse to run
// against. It is consulted before ControlCall is even attempted, so the
// message can be specific to the actual state rather than generic:
// ControlCall's own refusal error exists for the pool's internal
// bookkeeping, not to be read verbatim by an operator.
func stateUnavailableMessage(server, state string) (msg string, ok bool) {
	switch state {
	case "disabled":
		return fmt.Sprintf("server %q is disabled; set enabled = true in the config to use it", server), true
	case "connecting":
		return fmt.Sprintf("server %q is not connected (session=connecting); routes are not available yet", server), true
	case "listening":
		return fmt.Sprintf("server %q is waiting for the agent to connect; routes are not available yet", server), true
	case "auth_failed":
		return fmt.Sprintf("server %q permanently rejected authentication (auth_failed); routes are not available. Re-exchange pins and restart.", server), true
	default:
		// "connected" falls through to an actual relay attempt below. Any
		// other value is a session enum this package does not recognize yet
		// (the enum is declared open); it gets the same treatment as
		// "connected" rather than a dedicated branch that would need
		// updating every time the enum grows — the relay attempt itself
		// fails cleanly against a state that turns out not to have a live
		// client after all, the same way the "connected, dropped mid-call"
		// row below already does.
		return "", false
	}
}

// RoutesJSON implements ipc.RoutesProvider.
func (p *routesProvider) RoutesJSON(ctx context.Context, server string) ([]byte, error) {
	state, err := p.pool.EntryState(server)
	if err != nil {
		// Not in the pool at all — distinct from every state below, all of
		// which name a server the pool does know about. Reuses the pool's
		// own not-found error text rather than inventing a second string
		// for the same fact.
		return nil, &ipc.RoutesError{Status: 2, Msg: err.Error()}
	}
	if msg, unavailable := stateUnavailableMessage(server, state); unavailable {
		return nil, &ipc.RoutesError{Status: 3, Msg: msg}
	}

	var resp *controlpb.GetStatusResponse
	callErr := p.pool.ControlCall(ctx, server, func(cctx context.Context, c *control.Client) error {
		r, gerr := c.GetStatus(cctx, &controlpb.GetStatusRequest{})
		if gerr != nil {
			return gerr
		}
		resp = r
		return nil
	})
	if callErr != nil {
		if status.Code(callErr) == codes.Unimplemented {
			// The expected default until every paired agent is rebuilt, not
			// an exceptional error — named distinctly for the same reason
			// classifyDialError names an ALPN version mismatch distinctly,
			// so the operator rebuilds both ends instead of chasing
			// something else. The raw gRPC status string never reaches here.
			return nil, &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
				"the agent at server %q is running a version that does not report its routes; rebuild both ends", server)}
		}
		if status.Code(callErr) == codes.ResourceExhausted {
			// The reply did not fit in one message, so none of it arrived.
			// Nothing bounds a route table, and the size that decides this is
			// a limit held here rather than a condition of the far end or of
			// the network — so it must not be reported as a reconnection,
			// which invites an operator to wait for something that will not
			// change by itself.
			return nil, &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
				"server %q sent a larger route table than this daemon will accept in one reply; "+
					"this is a limit on this machine, not a fault on the network", server)}
		}
		// Any other failure at this point means the session looked
		// "connected" a moment ago but the call itself did not complete —
		// a mid-call drop, or (in reverse mode) a displacement by a newer
		// authenticated peer. Both are ordinary, expected textures of
		// failure for a live network call, not a special case: report it
		// the same way the CLI already reports a session that is
		// reconnecting elsewhere, rather than surfacing the internal
		// ControlCall error text verbatim. Collapsing the two is
		// deliberate for the operator, but the real error would otherwise
		// vanish with no trace, so it is kept at debug level in case this
		// branch is ever hit by an actual defect rather than a transient
		// drop.
		slog.Debug("routes: control call failed; reporting as reconnecting",
			"role", "daemon", "session", server, "err", callErr)
		return nil, &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q is reconnecting; try again", server)}
	}

	routes := make([]RouteInfo, len(resp.GetRoutes()))
	for i, r := range resp.GetRoutes() {
		routes[i] = RouteInfo{
			Target:     r.GetTarget(),
			Address:    r.GetAddress(),
			Builtin:    r.GetBuiltin(),
			Provenance: r.GetProvenance(),
		}
	}
	snap := RoutesSnapshot{Schema: 1, Server: server, Routes: routes}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal routes snapshot: %w", err)
	}
	return b, nil
}
