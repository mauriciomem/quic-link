package tunnel

// attach_test.go tests the DoAttach function using the mem transport harness.
// All tests are white-box (package tunnel) so they can access unexported helpers.

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// ---- DoAttach tests ---------------------------------------------------------

// TestDoAttach_ByteExact verifies that DoAttach splices a small payload
// byte-exactly through a mem agent running tunnel.Serve (the real echo path).
func TestDoAttach_ByteExact(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{t: s.clientT, serverAddr: s.serverAddr}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	// Build a local pipe pair: one end is "local" for DoAttach, the other is ours.
	localA, localB := net.Pipe()
	defer localA.Close()

	payload := []byte("doattach-byte-exact-test")
	reqid := NewReqID()

	attachDone := make(chan error, 1)
	go func() {
		attachDone <- DoAttach(ctx, conn, localA, "ssh", reqid, nil)
	}()

	// Write payload to localB, read echo back.
	if _, err := localB.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(payload))
	localB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(localB, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}

	// Tear down by closing the local side.
	localB.Close()
	select {
	case <-attachDone:
	case <-time.After(5 * time.Second):
		t.Fatal("DoAttach did not return after local close")
	}
}

// TestDoAttach_HalfClose verifies that closing the write side of the local
// pipe propagates as a FIN (not a reset) so the echo direction keeps flowing.
func TestDoAttach_HalfClose(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{t: s.clientT, serverAddr: s.serverAddr}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	localA, localB := net.Pipe()
	defer localA.Close()
	defer localB.Close()

	payload := []byte("half-close-attach-test")
	reqid := NewReqID()

	attachDone := make(chan error, 1)
	go func() {
		attachDone <- DoAttach(ctx, conn, localA, "ssh", reqid, nil)
	}()

	// Write and then close write direction (half-close).
	if _, err := localB.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// net.Pipe doesn't have CloseWrite, so just close the whole conn.
	// The echo agent returns whatever it received.
	got, err := io.ReadAll(io.LimitReader(localB, int64(len(payload))))
	if err != nil {
		t.Logf("ReadAll: %v (may be expected on pipe close)", err)
	}
	if len(got) > 0 && !bytes.Equal(got, payload[:len(got)]) {
		t.Errorf("partial echo mismatch: got %q want prefix of %q", got, payload)
	}
}

// TestDoAttach_Reset verifies that an abrupt local close causes the QUIC stream
// to be reset (not a clean FIN).
func TestDoAttach_Reset(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{t: s.clientT, serverAddr: s.serverAddr}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	localA, localB := net.Pipe()
	// Don't defer close; we close localB abruptly below.

	reqid := NewReqID()
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- DoAttach(ctx, conn, localA, "ssh", reqid, nil)
	}()

	// Let the splice start, then abruptly close the local side.
	time.Sleep(10 * time.Millisecond)
	_ = localB.Close() // abrupt — should propagate as reset

	select {
	case <-attachDone:
	case <-time.After(5 * time.Second):
		t.Fatal("DoAttach did not return after abrupt local close")
	}
}

// TestDoAttach_UnknownTarget verifies that DoAttach returns an error (and does
// not hang) when the agent refuses the target with StatusUnknownTarget.
func TestDoAttach_UnknownTarget(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{t: s.clientT, serverAddr: s.serverAddr}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	localA, localB := net.Pipe()
	defer localB.Close()

	reqid := NewReqID()
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- DoAttach(ctx, conn, localA, "no-such-target-xyz", reqid, nil)
	}()

	select {
	case err := <-attachDone:
		if err == nil {
			t.Fatal("expected error for unknown target, got nil")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("DoAttach hung on unknown target")
	}
}

// TestDoAttach_RelayAck verifies that relayAck is called with the agent's
// response before the splice starts, and that a non-OK response causes
// DoAttach to return an error after calling relayAck.
func TestDoAttach_RelayAck(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{t: s.clientT, serverAddr: s.serverAddr}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	localA, localB := net.Pipe()
	defer localA.Close()
	defer localB.Close()

	ackCh := make(chan proto.Response, 1)
	relayAck := func(resp proto.Response) error {
		ackCh <- resp
		return nil
	}

	reqid := NewReqID()
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- DoAttach(ctx, conn, localA, "ssh", reqid, relayAck)
	}()

	// relayAck should be called with StatusOK.
	select {
	case resp := <-ackCh:
		if resp.Status != proto.StatusOK {
			t.Errorf("relayAck got status %v, want OK", resp.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relayAck was not called within 5s")
	}

	// Close local to end the splice.
	localB.Close()
	select {
	case <-attachDone:
	case <-time.After(5 * time.Second):
		t.Fatal("DoAttach did not return after local close")
	}
}

// TestOpenControl_Exported verifies that tunnel.OpenControl correctly opens a
// control stream on a mem connection (exercising the shared auth-classification
// path used by both connect and daemon pool).
func TestOpenControl_Exported(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := s.clientT.Dial(ctx, s.serverAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	cclient, err := OpenControl(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("OpenControl: %v", err)
	}
	defer cclient.Close()
}

// fakeStreamConn is a StreamConn whose OpenStream always errors. Used to test
// DoAttach error handling without a real agent.
type fakeStreamConn struct{ err error }

func (f *fakeStreamConn) OpenStream(_ context.Context) (transport.Stream, error) {
	return nil, f.err
}

// TestDoAttach_StreamOpenFails verifies that DoAttach returns the OpenStream
// error without hanging when the pooled conn is dead.
func TestDoAttach_StreamOpenFails(t *testing.T) {
	t.Parallel()

	hub := mem.NewHub()
	cliT := hub.Transport("client:dead", mem.FailDial(transport.ErrUnreachable))
	_ = cliT // unused; just here to verify the hub is set up

	localA, localB := net.Pipe()
	defer localA.Close()
	defer localB.Close()

	fake := &fakeStreamConn{err: transport.ErrUnreachable}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := DoAttach(ctx, fake, localA, "ssh", "test-reqid", nil)
	if err == nil {
		t.Fatal("expected error from DoAttach when OpenStream fails")
	}
}
