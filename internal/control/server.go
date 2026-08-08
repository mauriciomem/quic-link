package control

import (
	"context"
	"path"
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
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	method := path.Base(info.FullMethod)
	if err := s.policy.Authorize(s.peer, method); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
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
		version:   opt.Version,
		startedAt: opt.StartedAt,
	}

	watcher := &connEndWatcher{done: make(chan struct{})}
	gs := grpc.NewServer(grpc.StatsHandler(watcher), grpc.UnaryInterceptor(srv.authorize))
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
