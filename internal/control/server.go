package control

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// server implements controlpb.ControlServer. Ping echoes the client's nonce and
// stamps the agent's clock; GetStatus is not yet implemented (left Unimplemented
// so a client requesting it gets a clean codes.Unimplemented rather than a
// broken stream).
type server struct {
	controlpb.UnimplementedControlServer
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
// until the stream closes or ctx is cancelled. It always returns nil-or-context
// error; the important signal to the caller is simply that it RETURNED — the
// control stream is dead and the session MUST be torn down.
func Serve(ctx context.Context, stream transport.Stream) error {
	watcher := &connEndWatcher{done: make(chan struct{})}
	gs := grpc.NewServer(grpc.StatsHandler(watcher))
	controlpb.RegisterControlServer(gs, server{})

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
