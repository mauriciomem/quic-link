package control

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"runtime/debug"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// server implements controlpb.ControlServer. Ping echoes the client's nonce
// and stamps the agent's clock; GetStatus (in status.go) reports the agent's
// build version, start time, and route table. UnimplementedControlServer is
// still embedded so any future RPC this struct doesn't yet implement gets a
// clean codes.Unimplemented rather than a broken stream.
//
// peer and policy exist so every RPC can be authorized against who is
// actually calling before it reaches its handler (see the authorize
// interceptor below). Authorization may always allow today, but the
// check-point itself must be real — it must see the real caller and be
// consulted on every call, not sit in the struct unread.
//
// routes, version, and startedAt are GetStatus's own data, carried on the
// same struct rather than a second one because a single per-session gRPC
// server is already built fresh in Serve below — there is no reuse across
// sessions for a second constructor to save work on.
type server struct {
	controlpb.UnimplementedControlServer
	peer      PeerIdentity
	policy    Policy
	routes    RouteSource
	vhosts    VhostSource
	names     VhostPublisher
	withdraw  VhostWithdrawer
	version   string
	startedAt time.Time
}

// ServeOpts carries optional, additive parameters for Serve. The zero value
// serves Ping only, with GetStatus reporting an empty route list and an
// empty version/start time — exactly the behavior every existing caller
// already gets, so adding fields here never breaks a caller that predates
// them.
type ServeOpts struct {
	// Routes supplies the route table for a GetStatus reply. Nil means
	// GetStatus reports an empty route list rather than failing — an agent
	// with nothing to report is a valid configuration, not an error.
	Routes RouteSource
	// Names supplies the ability to publish a name while the agent runs. Nil
	// means the agent cannot, and says so.
	//
	// The asymmetry with Routes above is deliberate. Being asked to report
	// something one has none of has an honest answer: nothing. Being asked to
	// change something and quietly not changing it has no honest answer at
	// all, so its absence is reported as a refusal rather than treated as
	// success.
	Names VhostPublisher
	// Withdraw supplies the ability to take a published name back. Nil means the
	// agent cannot, and says so — the same asymmetry Names has, and for the same
	// reason: being asked to change something and quietly not changing it has no
	// honest answer.
	Withdraw VhostWithdrawer
	// Vhosts supplies the published-name table for a listing. Nil means the
	// listing reports nothing, for the same reason Routes does: an agent that
	// publishes no names has an honest answer, which is that there are none.
	Vhosts VhostSource
	// Version is reported to a GetStatus caller as the agent's own build
	// version. Empty means unknown, not a build defect.
	Version string
	// StartedAt is reported to a GetStatus caller as StartedUnixMs. The zero
	// value means unknown; GetStatus leaves StartedUnixMs at zero for it
	// rather than reporting a clearly-wrong Unix timestamp for a zero
	// time.Time.
	StartedAt time.Time
}

// Ping echoes the nonce and reports the agent's wall clock. RTT is measured by
// the client from its own send/receive timestamps; agent_unix_ms is
// informational (cross-host clock skew makes it unsafe for RTT).
func (server) Ping(_ context.Context, req *controlpb.PingRequest) (*controlpb.PingResponse, error) {
	return &controlpb.PingResponse{
		Nonce:       req.GetNonce(),
		AgentUnixMs: time.Now().UnixMilli(),
	}, nil
}

// authorize is a grpc.UnaryServerInterceptor that consults policy before
// every unary RPC reaches its handler. Gating dispatch here rather than
// inside each method's own body means a future RPC (GetStatus, and whatever
// comes after it) is authorized automatically the moment it is registered
// with the gRPC server — nobody has to remember to add the check inside a
// new handler for it to be covered.
func (s server) authorize(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	method := path.Base(info.FullMethod)
	if err := s.policy.Authorize(s.peer, method); err != nil {
		// A refused call stops here and never reaches its handler, so a
		// change that was attempted and not permitted has to be written down
		// here or nowhere. It is the attempts nobody expected that an
		// operator most needs to be able to find afterwards.
		if changesTheAgent(method) {
			s.auditMutation(method, auditedName(req), verdictDenied, "not permitted")
		}
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return handler(ctx, req)
}

// contain turns a panic inside an RPC into an error for the caller.
//
// Without it, one unexpected value reaching one handler ends the whole process:
// nothing above this point recovers, so the agent stops serving every other
// session too, and a client's request is the thing that decides when. An agent
// is a long-running program that strangers talk to, and the blast radius of a
// mistake in one call has to be that call.
//
// The panic is re-reported as an internal error, deliberately without detail.
// Whatever went wrong is this program's fault, not something the caller can
// act on, and the value a panic carries is as likely to describe this agent's
// internals as anything else. The full detail goes to the log, where the
// operator can see it and the caller cannot.
//
// It is the outermost interceptor, so it also covers a panic in the
// authorization check that runs before dispatch.
func (s server) contain(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("a control-plane call failed unexpectedly and was contained",
				"role", "agent",
				"peer", s.peer.Short(),
				"method", path.Base(info.FullMethod),
				"cause", fmt.Sprint(r),
				"stack", string(debug.Stack()),
			)
			resp = nil
			err = status.Error(codes.Internal, "the agent could not complete that call")
		}
	}()
	return handler(ctx, req)
}

// connEndWatcher signals done when the single gRPC connection ends, so Serve
// can return the moment the control stream dies (control-stream closure is
// session death).
type connEndWatcher struct {
	done chan struct{}
	once sync.Once
}

func (w *connEndWatcher) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (*connEndWatcher) HandleRPC(context.Context, stats.RPCStats) {}
func (w *connEndWatcher) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (w *connEndWatcher) HandleConn(_ context.Context, s stats.ConnStats) {
	if _, ok := s.(*stats.ConnEnd); ok {
		w.once.Do(func() { close(w.done) })
	}
}

// Serve runs a single-connection gRPC server over the control stream and blocks
// until the stream closes or ctx is cancelled. peer is the session's
// authenticated caller, consulted by policy before every RPC reaches its
// handler; policy is nil-able (nil behaves as AllowAll, matching the rest of
// the tree's nil-means-allow-all convention). opts is variadic so every
// caller that predates GetStatus's data keeps compiling unchanged; at most
// the first value is used. It always returns nil-or-context error; the
// important signal to the caller is simply that it RETURNED — the control
// stream is dead and the session MUST be torn down.
func Serve(ctx context.Context, stream transport.Stream, peer PeerIdentity, policy Policy, opts ...ServeOpts) error {
	if policy == nil {
		policy = AllowAll{}
	}
	var opt ServeOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	srv := server{
		peer:      peer,
		policy:    policy,
		routes:    opt.Routes,
		vhosts:    opt.Vhosts,
		names:     opt.Names,
		withdraw:  opt.Withdraw,
		version:   opt.Version,
		startedAt: opt.StartedAt,
	}

	watcher := &connEndWatcher{done: make(chan struct{})}
	// Containment is outermost so that it also covers the authorization check,
	// which runs before any handler and is as capable of being handed
	// something unexpected as they are.
	//
	// MaxRecvMsgSize matches maxControlRecvMsgSize, the same 64 KiB bound
	// NewClient already applies to what this agent will accept from the
	// daemon's own replies (client.go), rather than gRPC's stock 4 MiB
	// default. The reasoning there is symmetric: the largest legitimate
	// request any current RPC needs is AddVhost/RemoveVhost's host field, a
	// hostname bounded at 253 bytes by router.ValidateVhostKey, plus a port
	// number — a few hundred bytes at most once framed. 64 KiB is already
	// generous headroom over that, chosen to match the client's own cap
	// rather than invent a second number, so a compromised-but-correctly-
	// pinned caller cannot use the stock 4 MiB default as amplification
	// against this agent's memory. Unlike the client-side cap, this one also
	// matters for cost incurred before authorization ever runs: gRPC
	// unmarshals a unary request before ChainUnaryInterceptor's authorize
	// step is consulted, so every read-only method (Ping, GetStatus,
	// ListVhosts — always callable, no operator opt-in required) and even a
	// denied mutation pays this parse cost regardless of what the policy
	// decides. Bounding it here is the only point that protects that cost,
	// not merely the successful call it precedes.
	gs := grpc.NewServer(
		grpc.StatsHandler(watcher),
		grpc.ChainUnaryInterceptor(srv.contain, srv.authorize),
		grpc.MaxRecvMsgSize(maxControlRecvMsgSize),
	)
	controlpb.RegisterControlServer(gs, srv)

	ln := NewSingleConnListener(NewConn(stream))
	serveErr := make(chan error, 1)
	go func() { serveErr <- gs.Serve(ln) }()

	select {
	case <-watcher.done: // control conn ended → session dead
	case <-ctx.Done():
	}

	gs.Stop()
	_ = ln.Close()
	<-serveErr // let the Serve goroutine unwind
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
