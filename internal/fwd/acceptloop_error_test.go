package fwd_test

// acceptloop_error_test.go covers the "genuine Accept fault" path directly:
// Run's own doc comment promises the local listener is closed once Run
// returns, unconditionally. Before this fix that promise only held when ctx
// cancellation triggered the close; any other Accept error (the realistic
// case being local fd exhaustion) fell through the "closed listener is the
// clean shutdown signal" branch, leaked the listener, and left no
// diagnostic at all.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/fwd"
)

// faultyListener's Accept always returns a *net.OpError unrelated to the
// listener's own Close() — the shape the reviewer used to prove the leak
// (a genuine fault, not our own shutdown-triggered close). Close is
// idempotent and observable via a channel that closes on the first call, so
// a test can assert it was actually invoked rather than merely returning
// without error.
type faultyListener struct {
	mu       sync.Mutex
	closedCh chan struct{}
	closed   bool
}

func newFaultyListener() *faultyListener {
	return &faultyListener{closedCh: make(chan struct{})}
}

func (l *faultyListener) Accept() (net.Conn, error) {
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("too many open files")}
}

func (l *faultyListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.closedCh)
	}
	return nil
}

func (l *faultyListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestForwarder_AcceptFault_ClosesListenerAndLogs is the direct regression
// test for the listener leak: a non-ErrClosed, non-shutdown-caused Accept
// error must still result in the listener being closed and the fault being
// logged, so Run's "once Run returns, the local listener is closed" promise
// holds unconditionally rather than only on the ctx-cancellation path.
func TestForwarder_AcceptFault_ClosesListenerAndLogs(t *testing.T) {
	var logBuf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	ln := newFaultyListener()
	att := &scriptedAttacher{dialAddr: "127.0.0.1:0"} // never called; Accept always fails first
	f := fwd.New("server1", "pg", ln, att, fwd.Options{})

	// A never-cancelled context: the fault must terminate Run on its own,
	// not because shutdown was requested.
	ctx := context.Background()
	done := runForwarder(f, ctx)
	waitDone(t, done, "Run (after a genuine Accept fault)")

	select {
	case <-ln.closedCh:
	case <-time.After(1 * time.Second):
		t.Fatal("listener was never closed after a genuine (non-shutdown) Accept fault")
	}

	if !bytes.Contains(logBuf.Bytes(), []byte("too many open files")) {
		t.Errorf("expected the Accept fault to be logged, got log output: %q", logBuf.String())
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("level=ERROR")) {
		t.Errorf("expected the Accept fault to be logged at error level, got log output: %q", logBuf.String())
	}
}
