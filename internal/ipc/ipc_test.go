package ipc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---- test helpers -----------------------------------------------------------

// stubStatus is a StatusProvider that returns fixed JSON.
type stubStatus struct {
	data []byte
	err  error
}

func (s *stubStatus) StatusJSON() ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.data, nil
}

// stubPool is an AttachPool returning a configured state or error.
// OpenConn returns errNotReady for servers not in the "connected" state,
// and errNoConn for unknown servers. Tests that need a live splice use
// the realAttachPool helper instead.
type stubPool struct {
	states map[string]string
	// conn is returned by OpenConn when the server state is "connected".
	// Nil means OpenConn returns an error (for not-ready / unknown-server tests).
	conn tunnel.StreamConn
}

func (p *stubPool) EntryState(server string) (string, error) {
	if st, ok := p.states[server]; ok {
		return st, nil
	}
	return "", fmt.Errorf("server %q not found", server)
}

func (p *stubPool) OpenConn(_ context.Context, server string) (tunnel.StreamConn, string, error) {
	st, ok := p.states[server]
	if !ok {
		return nil, "", fmt.Errorf("server %q not found", server)
	}
	if st != "connected" {
		return nil, "", fmt.Errorf("server %q is %s; not ready", server, st)
	}
	if p.conn == nil {
		return nil, "", fmt.Errorf("server %q: no conn configured in stub", server)
	}
	return p.conn, "stub1234", nil
}

// errNotReadyStreamConn is a StreamConn that always fails OpenStream.
type errNotReadyStreamConn struct{}

func (e *errNotReadyStreamConn) OpenStream(_ context.Context) (transport.Stream, error) {
	return nil, fmt.Errorf("stub: stream open failed")
}

// newMemSetupForIPC creates an in-memory agent (tunnel.Serve with echo target)
// and returns the client-side conn (as tunnel.StreamConn) for use as the
// stubPool connection. It also opens the control stream so the agent's open
// deadline does not fire during the test.
func newMemSetupForIPC(t *testing.T) tunnel.StreamConn {
	t.Helper()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (server): %v", err)
	}

	hub := mem.NewHub()
	srvAddr := "ipc-test-agent:1"
	srvT := hub.Transport(srvAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("ipc-test-client:1", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runTestEchoSrv(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	conn, err := cliT.Dial(ctx, srvAddr)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck

	// Open the control stream so the agent's 5s deadline does not close the session.
	cclient, err := tunnel.OpenControl(ctx, conn, "ipc-test", control.OpenOpts{})
	if err != nil {
		t.Logf("OpenControl: %v (agent may accept for short test)", err)
	} else if cclient != nil {
		t.Cleanup(func() { cclient.Close() }) //nolint:errcheck
	}

	return conn
}

func runTestEchoSrv(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n]) //nolint:errcheck
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}

// startServerWithOpts starts a Server with custom options and returns the socket path.
// Uses shortSocketPath to stay within the 104-byte sun_path limit on macOS.
func startServerWithOpts(t *testing.T, status ipc.StatusProvider, pool ipc.AttachPool, opts ipc.ServerOpts) string {
	t.Helper()
	// Use a unique short path based on pid+test name hash to avoid collisions.
	sock := fmt.Sprintf("/tmp/ql-ipc-opts-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%100000)
	t.Cleanup(func() { os.Remove(sock) })
	srv := ipc.NewServerWithOpts(sock, status, pool, opts)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sock
}

// startTestServer starts a Server on a short socket path and returns the path.
// The server is shut down and the socket removed on test cleanup.
// Uses a short /tmp path to stay within macOS's 104-byte sun_path limit.
func startTestServer(t *testing.T, status ipc.StatusProvider, pool ipc.AttachPool) string {
	t.Helper()
	sock := fmt.Sprintf("/tmp/ql-ipc-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1000000)
	t.Cleanup(func() { os.Remove(sock) })
	srv := ipc.NewServer(sock, status, pool)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
		os.Remove(sock)
	})
	return sock
}

// dialAndRaw opens a raw unix connection, sends req via IPC framing, reads back
// a Response, and returns it. It is used for testing cases that the Client API
// does not expose (e.g. wrong schema).
func dialAndRaw(t *testing.T, sockPath string, req ipc.Request) ipc.Response {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	resp, err := ipc.RoundTripConn(conn, req)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	return resp
}

// ---- tests ------------------------------------------------------------------

// TestRPCStatus verifies that a status RPC returns the snapshot JSON.
func TestRPCStatus(t *testing.T) {
	snap := []byte(`{"schema":1,"servers":[]}`)
	sock := startTestServer(t,
		&stubStatus{data: snap},
		&stubPool{},
	)

	c := ipc.NewClient(sock)
	got, err := c.StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}
	// Verify the body round-trips as equivalent JSON.
	var gotObj, wantObj interface{}
	if err := json.Unmarshal(got, &gotObj); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal(snap, &wantObj); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	gotCanon, _ := json.Marshal(gotObj)
	wantCanon, _ := json.Marshal(wantObj)
	if string(gotCanon) != string(wantCanon) {
		t.Errorf("status body mismatch:\n got:  %s\n want: %s", gotCanon, wantCanon)
	}
}

// TestRPCUnknownMethod verifies that an unknown RPC method returns a framed
// error response rather than panicking.
func TestRPCUnknownMethod(t *testing.T) {
	sock := startTestServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{},
	)
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "not_a_real_method",
	})
	if resp.Status == 0 {
		t.Errorf("expected non-zero status for unknown method, got 0")
	}
}

// TestSchemaMismatch verifies that a mismatched socket_schema returns a framed
// error with no action taken, and the response carries the daemon's actual schema.
func TestSchemaMismatch(t *testing.T) {
	sock := startTestServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{},
	)
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: 999, // wrong schema
		Kind:         "rpc",
		Method:       "status",
	})
	if resp.Status == 0 {
		t.Errorf("expected non-zero status for schema mismatch, got 0")
	}
	if resp.SocketSchema != ipc.SocketSchema {
		t.Errorf("response SocketSchema = %d, want %d", resp.SocketSchema, ipc.SocketSchema)
	}
}

// TestZeroSchema verifies that a zero socket_schema (absent field) is treated as
// a mismatch. A zero value is the CBOR default and signals a client predating
// schema versioning; the server must not act on it.
func TestZeroSchema(t *testing.T) {
	sock := startTestServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{},
	)
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: 0,
		Kind:         "rpc",
		Method:       "status",
	})
	if resp.Status == 0 {
		t.Errorf("expected non-zero status for zero schema, got 0")
	}
}

// TestClientErrDaemonAbsent verifies that dialing a non-existent socket path
// returns ErrDaemonAbsent.
func TestClientErrDaemonAbsent(t *testing.T) {
	// A path short enough to attempt; see shortSocketPath. The socket deliberately
	// does not exist, and a path too long to even try would fail for a different
	// reason and prove nothing about an absent daemon.
	c := ipc.NewClient(shortSocketPath(t))
	_, err := c.StatusJSON()
	if !errors.Is(err, ipc.ErrDaemonAbsent) {
		t.Errorf("got %v, want ErrDaemonAbsent", err)
	}
}

// TestAttachConnected verifies that an attach for a server in "connected" state
// returns status 0 (the ack). Uses an in-memory agent so the splice path is
// exercised end-to-end.
func TestAttachConnected(t *testing.T) {
	agentConn := newMemSetupForIPC(t)
	pool := &stubPool{
		states: map[string]string{"server1": "connected"},
		conn:   agentConn,
	}
	sock := startTestServer(t, &stubStatus{data: []byte(`{}`)}, pool)

	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "attach",
		Server:       "server1",
		Target:       "ssh",
	})
	if resp.Status != 0 {
		t.Errorf("attach ack status = %d, want 0; msg: %s", resp.Status, resp.Msg)
	}
}

// TestAttachMissingServer verifies that an attach for an unknown server returns
// a non-zero status.
func TestAttachMissingServer(t *testing.T) {
	sock := startTestServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{states: map[string]string{}},
	)
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "attach",
		Server:       "no-such-server",
		Target:       "ssh",
	})
	if resp.Status == 0 {
		t.Errorf("expected non-zero status for missing server, got 0")
	}
}

// TestAttachNotReady verifies that an attach for a server in "connecting" state
// returns a non-zero status.
func TestAttachNotReady(t *testing.T) {
	sock := startTestServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{states: map[string]string{"server1": "connecting"}},
	)
	resp := dialAndRaw(t, sock, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "attach",
		Server:       "server1",
		Target:       "ssh",
	})
	if resp.Status == 0 {
		t.Errorf("expected non-zero status for not-ready server, got 0")
	}
}
