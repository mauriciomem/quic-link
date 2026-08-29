package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// ExposeSnapshot is the reply to a successful publish request: what the agent
// published, and the port this machine is currently answering names on.
//
// The port is here rather than fetched separately because only the daemon knows
// it — it comes from the listener actually held, not from configuration, and
// there may be none — and because a caller needs both halves to name a URL that
// works. Two calls could straddle a moment where the answer changed.
type ExposeSnapshot struct {
	Schema   int    `json:"schema"`
	Server   string `json:"server"`
	Host     string `json:"host"`
	HTTPPort int    `json:"http_port"`
}

// exposeProvider implements ipc.ExposeProvider by relaying a publish request to
// a named server's agent through the session pool, and turning every way that
// can fail into its own named reason — the same treatment the route-table read
// already gets, for the same purpose: an operator has to be able to tell a
// server that is disabled from one still connecting from an agent too old to
// understand the request at all.
type exposeProvider struct {
	pool   SessionPool
	naming NamingListeners
}

// NewExposeProvider returns an ipc.ExposeProvider that relays publish requests
// through pool, reporting the naming port this daemon currently holds.
func NewExposeProvider(pool SessionPool, naming NamingListeners) ipc.ExposeProvider {
	return &exposeProvider{pool: pool, naming: naming}
}

// httpPort reports the port this machine answers names on, or zero if it is not
// answering any. It reads the listener rather than the configuration on purpose:
// a number from configuration describes an intention, and binding it can fail
// while the daemon carries on serving everything else.
func (p *exposeProvider) httpPort() int {
	if p.naming.HTTP == nil {
		return 0
	}
	if a, ok := p.naming.HTTP.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// ExposeJSON implements ipc.ExposeProvider.
func (p *exposeProvider) ExposeJSON(ctx context.Context, server, host string, port int) ([]byte, error) {
	// Refused before anything is asked of the agent. Publishing a name this
	// machine will not answer for produces a URL that cannot work, which is
	// worse than a refusal: the name would exist on the agent, unreachable
	// from here, and nothing would say why.
	httpPort := p.httpPort()
	if httpPort == 0 {
		return nil, &ipc.RoutesError{Status: 3, Msg: "this daemon is not answering names, so a " +
			"published name would not be reachable from here; check the naming setup with doctor"}
	}

	state, err := p.pool.EntryState(server)
	if err != nil {
		return nil, &ipc.RoutesError{Status: 2, Msg: err.Error()}
	}
	if msg, unavailable := stateUnavailableMessage(server, state); unavailable {
		return nil, &ipc.RoutesError{Status: 3, Msg: msg}
	}

	// Checked here as well as by the caller, because this is an exported entry
	// point and the narrowing below is silent: a value that does not fit would
	// arrive at the agent as a different number than anyone asked for.
	if port < 1 || port > 65535 {
		return nil, &ipc.RoutesError{Status: 2, Msg: fmt.Sprintf(
			"port %d is outside the usable range 1-65535", port)}
	}

	var resp *controlpb.AddVhostResponse
	callErr := p.pool.ControlCall(ctx, server, func(cctx context.Context, c *control.Client) error {
		r, aerr := c.AddVhost(cctx, &controlpb.AddVhostRequest{Host: host, Port: uint32(port)})
		if aerr != nil {
			return aerr
		}
		resp = r
		return nil
	})
	if callErr != nil {
		return nil, exposeFailure(server, callErr)
	}
	// A relay can report no error and still not have made the call — an entry
	// that has no session to speak over says so by declining to run it. Reading
	// a missing reply as success would print a working URL for a name nobody
	// published, which is the one outcome worse than a refusal.
	if resp == nil {
		return nil, &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q did not carry out the request; try again", server)}
	}

	snap := ExposeSnapshot{Schema: 1, Server: server, Host: resp.GetHost(), HTTPPort: httpPort}
	b, merr := json.Marshal(snap)
	if merr != nil {
		return nil, fmt.Errorf("marshal expose snapshot: %w", merr)
	}
	return b, nil
}

// exposeFailure names why a publish request did not succeed. Each case has a
// different remedy, so each gets its own message rather than one reason
// standing in for all of them.
func exposeFailure(server string, err error) error {
	switch status.Code(err) {
	case codes.Unimplemented:
		// Either an agent built before it could publish names, or one whose
		// operator has not allowed it. Both are answered by talking to whoever
		// runs that agent, which is why they read alike here.
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"the agent at server %q cannot publish names; it may predate the feature, "+
				"or its operator has not allowed remote changes", server)}
	case codes.PermissionDenied:
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"the agent at server %q refuses remote changes to what it publishes; "+
				"its operator can allow them", server)}
	case codes.AlreadyExists:
		// status.Convert(err).Message() is the connected agent's own gRPC
		// status text — worded by whoever answered this session's handshake,
		// which pinning proves the identity of but not the intentions of.
		// Carried raw here: routesErrorResponse (internal/ipc/server.go) is
		// this codebase's one documented sanitisation boundary for a
		// RoutesError.Msg, and sanitising twice on the way there produces a
		// mangled nested truncation marker if the first pass ever truncates,
		// with no benefit — nothing between here and that boundary logs or
		// otherwise acts on this string.
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q already publishes that name: %s", server, status.Convert(err).Message())}
	case codes.InvalidArgument:
		return &ipc.RoutesError{Status: 2, Msg: status.Convert(err).Message()}
	case codes.ResourceExhausted:
		// The request was fine and there was no room for it, which is neither a
		// mistake to correct nor a connection to wait out. The number is
		// deliberately not repeated here: it belongs to the agent's build,
		// which need not be this one's, and the listing is both authoritative
		// and already available.
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"the agent at server %q is holding as many published names as it will; "+
				"see them with: quic-link vhosts %s", server, server)}
	default:
		slog.Debug("expose: control call failed; reporting as reconnecting",
			"role", "daemon", "session", server, "err", err)
		return &ipc.RoutesError{Status: 3, Msg: fmt.Sprintf(
			"server %q is reconnecting; try again", server)}
	}
}
