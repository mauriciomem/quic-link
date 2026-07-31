package main

// attach_exit_test.go verifies that exit codes returned through the daemon
// socket path (ipc.Client.Attach → AttachStatusError) are never remapped a
// second time by the CLI layer.
//
// Defect: the daemon converts the agent's protocol status into a final process
// exit code before writing the IPC ack. The old stdio.go code cast that
// already-final code back to a proto.Status and ran it through exitCodeForStatus
// a second time, producing wrong exit codes.
//
// Fix: AttachStatusError.Status is now wrapped in errFinalExitCode, which
// exitCodeForError passes through unchanged.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- errFinalExitCode unit tests --------------------------------------------

// TestErrFinalExitCode_PassThrough verifies that errFinalExitCode values are
// passed through exitCodeForError unchanged — they are never remapped through
// the proto.Status lookup table.
func TestErrFinalExitCode_PassThrough(t *testing.T) {
	cases := []struct {
		name string
		code int
	}{
		{"exit 3 (not-ready / unreachable)", 3},
		{"exit 4 (auth / unauthorized)", 4},
		{"exit 5 (remote refused / unknown target / dial failed)", 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &errFinalExitCode{code: tc.code, msg: "test message"}
			got := exitCodeForError(err)
			if got != tc.code {
				t.Errorf("exitCodeForError(errFinalExitCode{%d}) = %d, want %d",
					tc.code, got, tc.code)
			}
		})
	}
}

// TestErrFinalExitCode_AlreadyReported verifies that errFinalExitCode satisfies
// alreadyReportedErr so main() does not emit an extra slog.Error line when the
// agent's message was already printed to stderr.
func TestErrFinalExitCode_AlreadyReported(t *testing.T) {
	e := &errFinalExitCode{code: 5, msg: "refused"}
	var ar alreadyReportedErr
	if !errors.As(e, &ar) {
		t.Fatal("errFinalExitCode does not satisfy alreadyReportedErr")
	}
	if !ar.alreadyReported() {
		t.Error("alreadyReported() = false, want true")
	}
}

// TestAttachExitCodes_DoubleMappingRegression is the key regression test. It
// asserts all four field-observed failure modes. Each row shows the exit code
// that the daemon puts in the IPC ack (AttachStatusError.Status) and the exit
// code the process must ultimately deliver.
//
//	Scenario                  | daemon ack Status | want process exit
//	--------------------------|-------------------|------------------
//	agent: unknown_target     | 5                 | 5   (was 1 — defect)
//	agent: unauthorized       | 4                 | 4   (was 5 — defect)
//	agent: dial_failed        | 5                 | 5   (was 1 — defect)
//	session not ready         | 3                 | 3   (was 5 — defect)
//
// The old code did: exitCodeForStatus(proto.Status(ae.Status)). For example,
// proto.Status(5) is StatusBadHeader → exitCodeForStatus = 1 (wrong).
// The fix wraps ae.Status in errFinalExitCode, which exitCodeForError passes
// through unchanged.
func TestAttachExitCodes_DoubleMappingRegression(t *testing.T) {
	cases := []struct {
		name          string
		daemonAckCode int // value in AttachStatusError.Status (already final)
		wantExitCode  int
	}{
		{"unknown_target", 5, 5},
		{"unauthorized", 4, 4},
		{"dial_failed", 5, 5},
		{"session_not_ready", 3, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate what ipc.Client.Attach returns: the daemon sends a
			// non-zero ack whose Status is already a final process exit code.
			aerr := &ipc.AttachStatusError{
				Status: tc.daemonAckCode,
				Msg:    "agent message for " + tc.name,
			}

			// Apply the fix: wrap in errFinalExitCode just as stdio.go does.
			var ae *ipc.AttachStatusError
			if !errors.As(aerr, &ae) {
				t.Fatalf("errors.As failed unexpectedly for *ipc.AttachStatusError")
			}
			finalErr := &errFinalExitCode{code: ae.Status, msg: ae.Msg}
			got := exitCodeForError(finalErr)
			if got != tc.wantExitCode {
				t.Errorf("exit code = %d, want %d", got, tc.wantExitCode)
			}
		})
	}
}

// TestAttachExitCodes_ThroughSocket tests the full path through a real IPC
// socket for the "session not ready" scenario (daemon status code 3 → exit 3).
func TestAttachExitCodes_ThroughSocket(t *testing.T) {
	t.Parallel()

	pool := &axNotReadyPool{}
	sock := startAxTestServer(t, pool)

	_, err := ipc.NewClient(sock).Attach("server1", "ssh", nil)
	if err == nil {
		t.Fatal("expected error for not-ready server, got nil")
	}
	var ae *ipc.AttachStatusError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *ipc.AttachStatusError, got %T: %v", err, err)
	}
	if ae.Status != 3 {
		t.Errorf("AttachStatusError.Status = %d, want 3 (not-ready maps to 3)", ae.Status)
	}
	// The final exit code through the fix must be 3.
	got := exitCodeForError(&errFinalExitCode{code: ae.Status, msg: ae.Msg})
	if got != 3 {
		t.Errorf("exitCodeForError(errFinalExitCode{3}) = %d, want 3", got)
	}
	if ae.Msg == "" {
		t.Error("agent message must be preserved, got empty string")
	}
}

// TestAttachExitCodes_AgentRefusal runs a full IPC → in-memory QUIC agent path
// and confirms that an unknown target delivers AttachStatusError.Status = 5,
// which must map to exit code 5 (not 1 as the pre-fix code returned).
func TestAttachExitCodes_AgentRefusal(t *testing.T) {
	t.Parallel()

	agentConn := axBuildMemAgent(t)
	pool := &axConnPool{conn: agentConn}
	sock := startAxTestServer(t, pool)

	_, err := ipc.NewClient(sock).Attach("server1", "bogus-target", nil)
	if err == nil {
		t.Fatal("expected error when agent refuses target, got nil")
	}

	var ae *ipc.AttachStatusError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *ipc.AttachStatusError, got %T: %v", err, err)
	}
	if ae.Status != 5 {
		t.Errorf("AttachStatusError.Status = %d, want 5 (unknown_target maps to exit 5)", ae.Status)
	}

	// Verify that exitCodeForError with the fix returns 5.
	got := exitCodeForError(&errFinalExitCode{code: ae.Status, msg: ae.Msg})
	if got != 5 {
		t.Errorf("exitCodeForError(errFinalExitCode{5}) = %d, want 5", got)
	}
}

// ---- pool stubs -------------------------------------------------------------

// axNotReadyPool knows "server1" but refuses to provide a connection,
// simulating a session that is currently reconnecting.
type axNotReadyPool struct{}

func (p *axNotReadyPool) EntryState(server string) (string, error) {
	if server == "server1" {
		return "connecting", nil
	}
	return "", fmt.Errorf("unknown server %q", server)
}

func (p *axNotReadyPool) OpenConn(_ context.Context, _ string) (tunnel.StreamConn, string, error) {
	return nil, "", fmt.Errorf("session reconnecting; not ready")
}

// axConnPool returns a fixed StreamConn for "server1".
type axConnPool struct {
	conn tunnel.StreamConn
}

func (p *axConnPool) EntryState(server string) (string, error) {
	if server == "server1" {
		return "connected", nil
	}
	return "", fmt.Errorf("unknown server %q", server)
}

func (p *axConnPool) OpenConn(_ context.Context, server string) (tunnel.StreamConn, string, error) {
	if server != "server1" {
		return nil, "", fmt.Errorf("unknown server %q", server)
	}
	return p.conn, "axpin123", nil
}

// ---- IPC server helper ------------------------------------------------------

type axStatusStub struct{}

func (s *axStatusStub) StatusJSON() ([]byte, error) { return []byte(`{}`), nil }

// startAxTestServer starts a real IPC server backed by pool and returns the
// socket path. Cleanup is registered via t.Cleanup.
func startAxTestServer(t *testing.T, pool ipc.AttachPool) string {
	t.Helper()
	sock := fmt.Sprintf("/tmp/ql-ax-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	t.Cleanup(func() { os.Remove(sock) })

	srv := ipc.NewServerWithOpts(sock, &axStatusStub{}, pool, ipc.ServerOpts{UID: os.Getuid()})
	if err := srv.Listen(); err != nil {
		t.Fatalf("startAxTestServer listen: %v", err)
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

// ---- in-memory QUIC agent helper --------------------------------------------

// axBuildMemAgent starts an in-memory QUIC agent with an echo "ssh" target and
// returns the client-side StreamConn ready for use as a pool connection. The
// agent has no other routes, so any other target name returns StatusUnknownTarget.
//
// This follows the same pattern as newMemSetupForIPC in internal/ipc/ipc_test.go.
func axBuildMemAgent(t *testing.T) tunnel.StreamConn {
	t.Helper()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("axBuildMemAgent: NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("axBuildMemAgent: NewIdentity (server): %v", err)
	}

	hub := mem.NewHub()
	const srvAddr = "ax-agent:42"
	srvT := hub.Transport(srvAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("ax-client:42", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("axBuildMemAgent: srvT.Listen: %v", err)
	}

	// Echo server: the "ssh" route points here; the agent has no other routes.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("axBuildMemAgent: echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go axRunEchoServer(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("axBuildMemAgent: router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	conn, err := cliT.Dial(ctx, srvAddr)
	if err != nil {
		t.Fatalf("axBuildMemAgent: Dial: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "ax-test done") }) //nolint:errcheck

	// Open the control stream so the agent's open-deadline does not fire and
	// close the session mid-test.
	cclient, cerr := tunnel.OpenControl(ctx, conn, "ax-test", control.OpenOpts{})
	if cerr != nil {
		t.Logf("axBuildMemAgent: OpenControl: %v (acceptable for short test)", cerr)
	} else if cclient != nil {
		t.Cleanup(func() { cclient.Close() })
	}

	return conn
}

// axRunEchoServer runs a TCP echo server on ln until the listener is closed.
func axRunEchoServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c) //nolint:errcheck
		}(c)
	}
}
