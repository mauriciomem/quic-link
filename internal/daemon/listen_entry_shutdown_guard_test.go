package daemon

// This file lives in package daemon rather than daemon_test because it calls
// promote directly, which is unexported (same precedent as
// listen_entry_failwaiters_test.go).
//
// What this test pins: promote must refuse to install a freshly-opened
// connection and control client once its context reports shutdown, even when
// the control stream underneath happened to open successfully. Before the
// guard covered both outcomes of the control-stream open, that refusal only
// ran inside the error branch, so a control stream that finished opening
// after shutdown had already started fell straight through to installation.
//
// Reaching that path with a real, already-cancelled context does not work as
// a test: a cancelled context also makes the control-stream open itself fail
// (deterministically, per the underlying gRPC dial checking ctx.Err() before
// dispatch), so promote never reaches the success branch at all — cancelling
// ctx and failing to open the control stream are, in the code as written, the
// same event. To exercise the success-branch guard specifically, this test
// uses a context wrapper that reports a non-nil Err() while never closing its
// Done() channel, so nothing downstream that reacts to cancellation
// propagation (the gRPC dial included) is disturbed — only a caller that
// explicitly consults ctx.Err(), which is exactly what the guard does, sees
// the shutdown signal.

import (
	"context"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// reportsShutdownWithoutCancelling wraps a real, live context but reports
// ctx.Err() as already failed. Its Done channel is inherited unchanged and
// never closes on its own, so anything downstream that waits on cancellation
// is unaffected — only an explicit ctx.Err() check observes the shutdown.
type reportsShutdownWithoutCancelling struct {
	context.Context
}

func (reportsShutdownWithoutCancelling) Err() error { return context.Canceled }

// TestListenEntry_Promote_RefusesInstallWhenCtxReportsShutdown exercises the
// guard on the success path of promote: a control stream that opens cleanly
// must still be refused, and closed rather than installed, once ctx reports
// shutdown is underway.
func TestListenEntry_Promote_RefusesInstallWhenCtxReportsShutdown(t *testing.T) {
	hub := mem.NewHub()
	daemonLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	const listenAt = "shutdown-guard-daemon:1"
	daemonT := hub.Transport(listenAt, mem.WithCert(daemonLeaf))
	ln, err := daemonT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	agentLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity agent: %v", err)
	}
	agentT := hub.Transport("shutdown-guard-agent:1", mem.WithCert(agentLeaf))

	// The agent side serves the connection for real, so the daemon's control
	// stream open genuinely succeeds — the guard has to refuse a connection
	// that is, in every other respect, ready to become the live session.
	agentCtx, agentCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer agentCancel()
	go func() {
		conn, derr := agentT.Dial(agentCtx, listenAt)
		if derr != nil {
			return
		}
		rtr, rerr := router.New(map[string]string{"ssh": "tcp://127.0.0.1:1"}, nil)
		if rerr != nil {
			return
		}
		tunnel.ServeConn(agentCtx, conn, rtr)
	}()

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer acceptCancel()
	conn, err := ln.Accept(acceptCtx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	e := &listenEntry{name: "shutdown-guard", waiting: make(chan struct{}), clock: WallClock{}}
	shutdownCtx := reportsShutdownWithoutCancelling{context.Background()}

	got := e.promote(shutdownCtx, conn)
	if got {
		t.Fatalf("promote returned true with ctx reporting shutdown; want false")
	}
	if e.current != nil {
		t.Errorf("e.current = %v, want nil: promote must not install a connection once ctx reports shutdown", e.current)
	}
	if e.controlClient != nil {
		t.Errorf("e.controlClient = %v, want nil: promote must not install a control client once ctx reports shutdown", e.controlClient)
	}
}
