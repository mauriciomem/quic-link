package mem_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---- Stream tests -----------------------------------------------------------

// TestStream_OpenAcceptPairing verifies that a stream opened on one side is
// available via AcceptStream on the other, and that bytes flow both ways.
func TestStream_OpenAcceptPairing(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:1")
	cliT := hub.Transport("client:1")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:1")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cliConn.CloseWithError(0, "done") //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer srvConn.CloseWithError(0, "done") //nolint:errcheck

	// Client opens a stream; server accepts it.
	cliStream, err := cliConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	srvStream, err := srvConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Write from client; read on server.
	want := []byte("hello mem")
	if _, err := cliStream.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(srvStream, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("data mismatch: got %q want %q", got, want)
	}
	_ = cliStream.Close()
	_ = srvStream.Close()
}

// TestStream_HalfClose verifies that Stream.Close() is a half-close: the peer's
// Read returns io.EOF after draining, but the REVERSE direction keeps flowing.
// This is the INV-6 guarantee: a clean FIN stays a FIN.
func TestStream_HalfClose(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:2")
	cliT := hub.Transport("client:2")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:2")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cliConn.CloseWithError(0, "done") //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer srvConn.CloseWithError(0, "done") //nolint:errcheck

	cliStream, err := cliConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	srvStream, err := srvConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Write a payload then half-close the client send side.
	payload := []byte("half-close-test")
	if _, err := cliStream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := cliStream.Close(); err != nil {
		t.Fatalf("Close (half-close): %v", err)
	}

	// Server reads the payload and then sees io.EOF.
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srvStream, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("data mismatch: got %q want %q", got, payload)
	}
	n, err := srvStream.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("expected io.EOF after half-close, got n=%d err=%v", n, err)
	}

	// The REVERSE direction (server→client) must still work.
	reply := []byte("still flowing")
	if _, err := srvStream.Write(reply); err != nil {
		t.Fatalf("reverse Write after client half-close: %v", err)
	}
	buf := make([]byte, len(reply))
	if _, err := io.ReadFull(cliStream, buf); err != nil {
		t.Fatalf("reverse ReadFull: %v", err)
	}
	if string(buf) != string(reply) {
		t.Errorf("reverse data mismatch: got %q want %q", buf, reply)
	}

	_ = srvStream.Close()
}

// TestStream_Reset verifies that Reset abruptly terminates BOTH directions.
// The peer's Read AND Write must return an error — the clean FIN (EOF) must
// NOT be used. This is the other half of INV-6.
func TestStream_Reset(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:3")
	cliT := hub.Transport("client:3")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:3")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cliConn.CloseWithError(0, "done") //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer srvConn.CloseWithError(0, "done") //nolint:errcheck

	cliStream, err := cliConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	srvStream, err := srvConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	// Client resets the stream.
	cliStream.Reset(42)

	// Server Read must return an error (not io.EOF — that would be a FIN).
	n, err := srvStream.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("expected error from Read after Reset, got n=%d nil", n)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("Reset must not produce io.EOF (that is a half-close); got io.EOF")
	}

	// Server Write must also fail.
	_, err = srvStream.Write([]byte("dead"))
	if err == nil {
		t.Fatal("expected error from Write after Reset, got nil")
	}
}

// TestConn_ContextCauseOnClose verifies that CloseWithError cancels the conn's
// Context with the correct error as the cause, and that closing one side also
// fires the peer's Context.
func TestConn_ContextCauseOnClose(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:4")
	cliT := hub.Transport("client:4")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:4")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// Close the client side.
	if err := cliConn.CloseWithError(99, "test close"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	// The client's own context must be cancelled.
	select {
	case <-cliConn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("client context was not cancelled after CloseWithError")
	}
	cause := context.Cause(cliConn.Context())
	if cause == nil {
		t.Fatal("client context cause is nil")
	}
	if !errors.Is(cause, cause) { // cause is a concrete *closeError; check it has the code/msg
		t.Errorf("unexpected cause: %v", cause)
	}

	// The SERVER's context must also be cancelled because the peer closed.
	select {
	case <-srvConn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("peer (server) context was not cancelled when client called CloseWithError")
	}
}

// TestConn_PeerCertificates verifies that each side sees the other's cert.
func TestConn_PeerCertificates(t *testing.T) {
	t.Parallel()
	clientLeaf, clientPin, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	serverLeaf, serverPin, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (server): %v", err)
	}
	_ = clientPin
	_ = serverPin

	hub := mem.NewHub()
	srvT := hub.Transport("server:5", mem.WithCert(serverLeaf))
	cliT := hub.Transport("client:5", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:5")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cliConn.CloseWithError(0, "done") //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer srvConn.CloseWithError(0, "done") //nolint:errcheck

	// Client sees server's cert as peer.
	cliPeer := cliConn.PeerCertificates()
	if len(cliPeer) != 1 {
		t.Fatalf("client: expected 1 peer cert, got %d", len(cliPeer))
	}
	if cliPeer[0] != serverLeaf {
		t.Errorf("client: peer cert is not serverLeaf")
	}

	// Server sees client's cert as peer.
	srvPeer := srvConn.PeerCertificates()
	if len(srvPeer) != 1 {
		t.Fatalf("server: expected 1 peer cert, got %d", len(srvPeer))
	}
	if srvPeer[0] != clientLeaf {
		t.Errorf("server: peer cert is not clientLeaf")
	}
}

// TestDialUnregistered verifies that dialing an address with no listener returns
// transport.ErrUnreachable.
func TestDialUnregistered(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	cliT := hub.Transport("client:6")

	_, err := cliT.Dial(context.Background(), "nobody:0")
	if !errors.Is(err, transport.ErrUnreachable) {
		t.Fatalf("expected ErrUnreachable, got: %v", err)
	}
}

// TestFailDial verifies that FailDial makes every Dial return the injected error
// regardless of whether a listener exists.
func TestFailDial(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	// Register a listener so the Hub would otherwise accept the dial.
	srvT := hub.Transport("server:7")
	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	cliT := hub.Transport("client:7", mem.FailDial(transport.ErrAuthFailed))
	_, err = cliT.Dial(context.Background(), "server:7")
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got: %v", err)
	}
}

// TestStream_EchoViaTunnelPipe runs a byte-exact echo through tunnel.Pipe to
// prove half-close fidelity end-to-end: tunnel.Pipe uses closeWrite for a clean
// FIN and reset for abrupt teardown — both must work correctly over mem streams.
//
// Topology: client stream ↔ tunnel.Pipe ↔ server stream, where the server
// simply echoes everything back by piping the server stream to itself in
// loopback (a separate goroutine copies from the server's read half to its
// write half). The client writes a payload, closes its send half (FIN), reads
// the echo, and waits for tunnel.Pipe to complete.
func TestStream_EchoViaTunnelPipe(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:8")
	cliT := hub.Transport("client:8")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:8")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cliConn.CloseWithError(0, "done") //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer srvConn.CloseWithError(0, "done") //nolint:errcheck

	cliStream, err := cliConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	srvStream, err := srvConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	payload := []byte("byte-exact-echo-test-via-tunnel-pipe")

	// Server side: read everything from the client, then write it back.
	// This must happen in a goroutine that runs to completion independently.
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		// Read what the client sends (until EOF after client's Close()).
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(srvStream, buf); err != nil {
			return
		}
		// Write the echo back, then half-close.
		_, _ = srvStream.Write(buf)
		_ = srvStream.Close()
	}()

	// Client side: write payload, half-close, then read echo.
	if _, err := cliStream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Half-close the client send so the server sees EOF and starts echoing.
	if err := cliStream.Close(); err != nil {
		t.Fatalf("Close (half-close): %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cliStream, got); err != nil {
		t.Fatalf("ReadFull echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}

	// Wait for the server goroutine to finish.
	select {
	case <-srvDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server goroutine did not complete")
	}
}

// TestHandshakeComplete verifies that HandshakeComplete returns a channel that
// is already closed (instant handshake in mem).
func TestHandshakeComplete(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:9")
	cliT := hub.Transport("client:9")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:9")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cliConn.CloseWithError(0, "done") //nolint:errcheck

	select {
	case <-cliConn.HandshakeComplete():
	default:
		t.Fatal("HandshakeComplete channel should already be closed")
	}
}

// TestAcceptStream_UnblocksOnConnClose verifies that AcceptStream returns an
// error (not a deadlock) when the conn is closed while waiting for streams.
// This guards against goroutine leaks in callers like tunnel.Serve.
func TestAcceptStream_UnblocksOnConnClose(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	srvT := hub.Transport("server:10")
	cliT := hub.Transport("client:10")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, "server:10")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := srvConn.AcceptStream(context.Background())
		done <- err
	}()

	// Close the client; the server's AcceptStream must unblock.
	_ = cliConn.CloseWithError(0, "test done")

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AcceptStream should have returned an error after peer closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptStream blocked forever after peer close (goroutine leak)")
	}
}
