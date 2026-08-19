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

// WithdrawSnapshot is the JSON-serializable body of a successful withdrawal.
type WithdrawSnapshot struct {
	Schema int    `json:"schema"`
	Server string `json:"server"`
	Host   string `json:"host"`
	// ShadowedBy names a pattern that resumes serving the name now the exact
	// entry is gone, and is absent when nothing does. A withdrawal can be true
	// and still leave the name answered, at a different address; a caller told
	// only that it succeeded would have no way to find that out.
	ShadowedBy string `json:"shadowed_by,omitempty"`
}

type withdrawProvider struct {
	pool SessionPool
}

// NewWithdrawProvider returns an ipc.WithdrawProvider that relays withdrawal
// requests through pool.
func NewWithdrawProvider(pool SessionPool) ipc.WithdrawProvider {
	return &withdrawProvider{pool: pool}
}

// WithdrawJSON implements ipc.WithdrawProvider.
func (p *withdrawProvider) WithdrawJSON(ctx context.Context, server, host string) ([]byte, error) {
	state, err := p.pool.EntryState(server)
	if err != nil {
		return nil, &ipc.RoutesError{Status: 2, Msg: err.Error()}
	}
	if msg, unavailable := stateUnavailableMessage(server, state); unavailable {
		return nil, &ipc.RoutesError{Status: 3, Msg: msg}
	}

	var resp *controlpb.RemoveVhostResponse
	callErr := p.pool.ControlCall(ctx, server, func(cctx context.Context, c *control.Client) error {
		r, rerr := c.RemoveVhost(cctx, &controlpb.RemoveVhostRequest{Host: host})
		if rerr != nil {
			return rerr
		}
		resp = r
		return nil
	})
	if callErr != nil {
		return nil, withdrawFailure(server, host, callErr)
	}

	snap := WithdrawSnapshot{
		Schema:     1,
		Server:     server,
		Host:       resp.GetHost(),
		ShadowedBy: resp.GetShadowedBy(),
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal withdraw snapshot: %w", err)
	}
	return b, nil
}

// withdrawFailure turns a failed withdrawal into the one reason and status that
// belong to it.
//
// A name that came from the agent's configuration arrives here as a failed
// precondition rather than a denied permission, and is answered as one. The
// distinction is the whole point: a permission error invites asking the agent's
// operator to allow something, and no setting they could change makes their own
// configuration remotely removable. Sending someone to look for that switch
// would waste their time and teach them something untrue.
func withdrawFailure(server, host string, err error) error {
	switch status.Code(err) {
	case codes.Unimplemented:
		// Either an agent built before it could withdraw names, or one whose
		// operator has not allowed remote changes. Both are answered by talking
		// to whoever runs that agent.
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"the agent at server %q cannot withdraw names; it may predate the feature, "+
				"or its operator has not allowed remote changes", server)}
	case codes.PermissionDenied:
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"the agent at server %q refuses remote changes to what it publishes; "+
				"its operator can allow them", server)}
	case codes.NotFound:
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q does not publish %q, so there is nothing to withdraw", server, host)}
	case codes.FailedPrecondition:
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q publishes %q from its own configuration, which cannot be withdrawn "+
				"from here; the operator of that agent decides what it configures", server, host)}
	case codes.InvalidArgument:
		return &ipc.RoutesError{Status: 2, Msg: status.Convert(err).Message()}
	default:
		slog.Debug("withdraw: control call failed; reporting as reconnecting",
			"role", "daemon", "session", server, "err", err)
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q is reconnecting; try again", server)}
	}
}
