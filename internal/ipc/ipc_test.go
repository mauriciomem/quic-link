package ipc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/ipc"
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
type stubPool struct {
	states map[string]string
}

func (p *stubPool) EntryState(server string) (string, error) {
	if st, ok := p.states[server]; ok {
		return st, nil
	}
	return "", fmt.Errorf("server %q not found", server)
}

// startTestServer starts a Server in a temp dir and returns the socket path.
// The server is shut down and the socket removed on test cleanup.
func startTestServer(t *testing.T, status ipc.StatusProvider, pool ipc.AttachPool) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "daemon.sock")
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
	dir := t.TempDir()
	c := ipc.NewClient(filepath.Join(dir, "missing.sock"))
	_, err := c.StatusJSON()
	if !errors.Is(err, ipc.ErrDaemonAbsent) {
		t.Errorf("got %v, want ErrDaemonAbsent", err)
	}
}

// TestAttachConnected verifies that an attach for a server in "connected" state
// returns status 0 (the ack stub).
func TestAttachConnected(t *testing.T) {
	sock := startTestServer(t,
		&stubStatus{data: []byte(`{}`)},
		&stubPool{states: map[string]string{"server1": "connected"}},
	)
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
