package daemon_test

// routes_test.go tests the daemon's routesProvider — the adapter that turns
// a pool.ControlCall relay into ipc.RoutesProvider, mapping every way the
// relay can fail short of success into its own distinguishable, named
// result, one per session state.
//
// The state-table tests (disabled, connecting, listening, auth_failed,
// unknown server, mid-call failure) drive the real production
// routesProvider against a small fake SessionPool: the mapping under test
// is a pure function of (EntryState result, ControlCall outcome) -> message,
// so a fake pool proves the mapping without paying for a real transport per
// state. The two end-to-end tests (success, and the Unimplemented
// degradation) instead drive the real pool and a real control.Client, per
// the project's "prefer a real client over a hand-written fixture" rule —
// see TestRoutesJSON_Connected_ReturnsRealRoutes and
// TestRoutesJSON_UnimplementedAgent_NamesTheStaleVersion below.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// ---- fake pool for isolated mapping tests ----------------------------------

// fakeRoutesPool is a minimal daemon.SessionPool whose EntryState and
// ControlCall are independently configurable, so a test can drive
// routesProvider through exactly one state at a time without standing up a
// real transport for every one of the state table's rows.
type fakeRoutesPool struct {
	state     string
	stateErr  error
	controlFn func(ctx context.Context, fn func(context.Context, *control.Client) error) error
}

func (p *fakeRoutesPool) Get(context.Context, string) (daemon.Conn, error) {
	return nil, errors.New("fakeRoutesPool: Get not implemented")
}
func (p *fakeRoutesPool) State() []daemon.SessionState { return nil }
func (p *fakeRoutesPool) EntryState(string) (string, error) {
	return p.state, p.stateErr
}
func (p *fakeRoutesPool) ControlCall(ctx context.Context, _ string, fn func(context.Context, *control.Client) error) error {
	if p.controlFn == nil {
		return errors.New("fakeRoutesPool: ControlCall not configured for this test")
	}
	return p.controlFn(ctx, fn)
}
func (p *fakeRoutesPool) Close() {}

var _ daemon.SessionPool = (*fakeRoutesPool)(nil)

// ---- the state table --------------------------------------------------------

// TestRoutesJSON_StateTable proves each degraded session state produces its
// own distinct, exact message and status — not a shared "not available"
// string standing in for all four. fn must never be invoked for any of
// these: none of them has a live control client to call it with.
func TestRoutesJSON_StateTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		state      string
		wantStatus uint
		wantMsg    string
	}{
		{
			name:       "disabled",
			state:      "disabled",
			wantStatus: 3,
			wantMsg:    `server "srv" is disabled; set enabled = true in the config to use it`,
		},
		{
			name:       "connecting",
			state:      "connecting",
			wantStatus: 3,
			wantMsg:    `server "srv" is not connected (session=connecting); routes are not available yet`,
		},
		{
			name:       "listening",
			state:      "listening",
			wantStatus: 3,
			wantMsg:    `server "srv" is waiting for the agent to connect; routes are not available yet`,
		},
		{
			name:       "auth_failed",
			state:      "auth_failed",
			wantStatus: 3,
			wantMsg:    `server "srv" permanently rejected authentication (auth_failed); routes are not available. Re-exchange pins and restart.`,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pool := &fakeRoutesPool{
				state: tc.state,
				controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
					t.Error("ControlCall was invoked for a state with no live control client")
					return nil
				},
			}
			provider := daemon.NewRoutesProvider(pool)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := provider.RoutesJSON(ctx, "srv")
			if err == nil {
				t.Fatal("RoutesJSON succeeded for a degraded state")
			}
			var re *ipc.RoutesError
			if !errors.As(err, &re) {
				t.Fatalf("RoutesJSON error is not *ipc.RoutesError: %v", err)
			}
			if re.Status != tc.wantStatus {
				t.Errorf("Status = %d, want %d", re.Status, tc.wantStatus)
			}
			if re.Msg != tc.wantMsg {
				t.Errorf("Msg = %q, want %q", re.Msg, tc.wantMsg)
			}
		})
	}
}

// TestRoutesJSON_AuthFailed_NeverSaysReconnecting proves the auth_failed
// message specifically never uses "reconnect" wording — nothing is going to
// reconnect on its own from a permanent authentication rejection, and
// saying so would actively mislead an operator into waiting for a recovery
// that will never happen. This is asserted as its own test, separately from
// the state table's exact-string check above, so a future edit to the
// auth_failed wording that keeps the string exact but reintroduces
// "reconnect" elsewhere in a refactor still gets caught by name.
func TestRoutesJSON_AuthFailed_NeverSaysReconnecting(t *testing.T) {
	t.Parallel()
	pool := &fakeRoutesPool{state: "auth_failed"}
	provider := daemon.NewRoutesProvider(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := provider.RoutesJSON(ctx, "srv")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("RoutesJSON error is not *ipc.RoutesError: %v", err)
	}
	if strings.Contains(strings.ToLower(re.Msg), "reconnect") {
		t.Errorf("auth_failed message mentions reconnecting, which never happens on its own: %q", re.Msg)
	}
}

// TestRoutesJSON_UnknownServer proves a server name absent from the pool
// entirely reuses the pool's own not-found error shape, at its own distinct
// status (2, matching the config-lookup-miss bucket), rather than inventing
// a second string for the same fact or lumping it in with the degraded
// live-session states above (which are all status 3).
func TestRoutesJSON_UnknownServer(t *testing.T) {
	t.Parallel()
	notFound := fmt.Errorf(`unknown server "srv"`)
	pool := &fakeRoutesPool{stateErr: notFound}
	provider := daemon.NewRoutesProvider(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := provider.RoutesJSON(ctx, "srv")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("RoutesJSON error is not *ipc.RoutesError: %v", err)
	}
	if re.Status != 2 {
		t.Errorf("Status = %d, want 2", re.Status)
	}
	if re.Msg != notFound.Error() {
		t.Errorf("Msg = %q, want the pool's own not-found text %q", re.Msg, notFound.Error())
	}
}

// TestRoutesJSON_ConnectedButControlCallFails_ReportsReconnecting proves the
// last row of the table: a session that looked "connected" at the state
// check but whose control-plane call itself failed (a mid-call drop or
// displacement — see TestControlCall_DisplacedMidCall_FailsCleanly in
// control_call_test.go for how that interleaving actually arises in
// production) is reported as an ordinary "reconnecting" condition rather
// than surfacing the raw internal ControlCall error text.
func TestRoutesJSON_ConnectedButControlCallFails_ReportsReconnecting(t *testing.T) {
	t.Parallel()
	pool := &fakeRoutesPool{
		state: "connected",
		controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
			return errors.New("server \"srv\": no control client available (session=connecting)")
		},
	}
	provider := daemon.NewRoutesProvider(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := provider.RoutesJSON(ctx, "srv")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("RoutesJSON error is not *ipc.RoutesError: %v", err)
	}
	if re.Status != 3 {
		t.Errorf("Status = %d, want 3", re.Status)
	}
	const want = `server "srv" is reconnecting; try again`
	if re.Msg != want {
		t.Errorf("Msg = %q, want %q", re.Msg, want)
	}
}

// TestRoutesJSON_ConnectedButControlCallFails_LogsUnderlyingError proves the
// mid-call failure that gets collapsed into the generic "reconnecting"
// message for the operator is not silently discarded: the real error still
// reaches the log at debug level, so a genuine defect hitting this path
// leaves a trace for whoever investigates it, while the user-facing message
// and status stay exactly as generic as the previous test expects.
func TestRoutesJSON_ConnectedButControlCallFails_LogsUnderlyingError(t *testing.T) {
	buf := captureLogs(t)
	pool := &fakeRoutesPool{
		state: "connected",
		controlFn: func(context.Context, func(context.Context, *control.Client) error) error {
			return errors.New("boom: distinctive underlying failure text")
		},
	}
	provider := daemon.NewRoutesProvider(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := provider.RoutesJSON(ctx, "srv")
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("RoutesJSON error is not *ipc.RoutesError: %v", err)
	}
	if re.Status != 3 {
		t.Errorf("Status = %d, want 3 (unchanged by adding the log line)", re.Status)
	}
	const wantMsg = `server "srv" is reconnecting; try again`
	if re.Msg != wantMsg {
		t.Errorf("Msg = %q, want %q (unchanged by adding the log line)", re.Msg, wantMsg)
	}
	if !strings.Contains(buf.String(), "boom: distinctive underlying failure text") {
		t.Errorf("underlying error was not logged; log output = %s", buf.String())
	}
}

// ---- end to end: the real relay against a real in-memory agent ------------

// TestRoutesJSON_Connected_ReturnsRealRoutes drives routesProvider against
// the package's own real-pool rig (control_call_test.go's newForwardRig),
// the same production dialEntry, ControlCall, and in-memory agent
// TestControlCall_Connected_InvokesFnWithAWorkingClient already trusts, and
// asserts the actual route data — including the real provenance
// distinction, per internal/router's own rules — round-trips through the
// full relay.
func TestRoutesJSON_Connected_ReturnsRealRoutes(t *testing.T) {
	t.Parallel()
	r := newForwardRig(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.connect(t, ctx)

	provider := daemon.NewRoutesProvider(r.pool)
	body, err := provider.RoutesJSON(ctx, r.server)
	if err != nil {
		t.Fatalf("RoutesJSON: %v", err)
	}

	var snap daemon.RoutesSnapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, body)
	}
	if snap.Server != r.server {
		t.Errorf("Server = %q, want %q", snap.Server, r.server)
	}
	byName := make(map[string]daemon.RouteInfo, len(snap.Routes))
	for _, rt := range snap.Routes {
		byName[rt.Target] = rt
	}
	ssh, ok := byName["ssh"]
	if !ok {
		t.Fatal("no ssh route in the relayed snapshot")
	}
	if ssh.Builtin {
		t.Error("ssh route Builtin = true, want false — newForwardRig's agent overrides it")
	}
	if _, ok := byName["docker"]; !ok {
		t.Error("no docker route in the relayed snapshot")
	}
}

// TestRoutesRelay_EndToEnd_OverIPC proves the full five-layer relay —
// raw IPC socket -> handleRPC("routes") -> the daemon's routesProvider ->
// pool.ControlCall -> a real *control.Client -> a real in-memory agent's
// real GetStatus handler — connects end to end, not merely that each layer
// is correct in isolation.
func TestRoutesRelay_EndToEnd_OverIPC(t *testing.T) {
	t.Parallel()
	r := newForwardRig(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.connect(t, ctx)

	sock := fmt.Sprintf("/tmp/ql-routes-e2e-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	t.Cleanup(func() { os.Remove(sock) })

	srv := ipc.NewServer(sock, noStatusProvider{}, noAttachPool{})
	srv.SetRoutes(daemon.NewRoutesProvider(r.pool))
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(srvCtx)
	}()
	t.Cleanup(func() {
		srvCancel()
		<-done
	})

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp, err := ipc.RoundTripConn(conn, ipc.Request{
		SocketSchema: ipc.SocketSchema,
		Kind:         "rpc",
		Method:       "routes",
		Server:       r.server,
	})
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if resp.Status != 0 {
		t.Fatalf("routes rpc failed: status=%d msg=%q", resp.Status, resp.Msg)
	}

	var snap daemon.RoutesSnapshot
	if err := json.Unmarshal(resp.Body, &snap); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, resp.Body)
	}
	if len(snap.Routes) == 0 {
		t.Fatal("no routes in the end-to-end relay response")
	}
}

// noStatusProvider and noAttachPool satisfy ipc.NewServer's required
// dependencies for TestRoutesRelay_EndToEnd_OverIPC, which exercises only
// the "routes" RPC; both fail loudly if the test ever accidentally reaches
// them, rather than silently returning zero values.
type noStatusProvider struct{}

func (noStatusProvider) StatusJSON() ([]byte, error) {
	return nil, errors.New("noStatusProvider: not used by this test")
}

type noAttachPool struct{}

func (noAttachPool) EntryState(string) (string, error) {
	return "", errors.New("noAttachPool: not used by this test")
}
func (noAttachPool) OpenConn(context.Context, string) (tunnel.StreamConn, string, error) {
	return nil, "", errors.New("noAttachPool: not used by this test")
}

// ---- the Unimplemented degradation: a real seam, not a fabricated error ---

// staleAgentServer mimics a real agent built before GetStatus existed: Ping
// works, and GetStatus is left unoverridden, so it falls through to
// UnimplementedControlServer's own codes.Unimplemented reply — the exact
// status a real production peer would produce, not a value the test
// fabricates. This is the injection seam for the test below: everything
// downstream of this server — the real *control.Client, the real gRPC round
// trip, and routesProvider's real, unmodified production error-mapping
// code — runs exactly as it would in production. Only the "agent" is
// swapped for one that predates GetStatus, which is the one condition that
// cannot occur naturally in this repository's own CI, since every test
// build pairs a client and an agent compiled from the same commit.
type staleAgentServer struct {
	controlpb.UnimplementedControlServer
}

func (staleAgentServer) Ping(_ context.Context, req *controlpb.PingRequest) (*controlpb.PingResponse, error) {
	return &controlpb.PingResponse{Nonce: req.GetNonce(), AgentUnixMs: time.Now().UnixMilli()}, nil
}

// pairControlStreams pairs two in-memory transport.Stream endpoints, the
// same shape internal/control/authz_test.go's pairStreams builds, duplicated
// here because that helper is unexported and this package must not grow a
// test-only dependency on another package's _test files.
func pairControlStreams(t *testing.T, name string) (client, server transport.Stream) {
	t.Helper()
	hub := mem.NewHub()
	srvAddr := name + "-srv:1"
	srvT := hub.Transport(srvAddr)
	cliT := hub.Transport(name + "-cli:1")

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx := context.Background()
	cliConn, err := cliT.Dial(ctx, srvAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { cliConn.CloseWithError(0, "test done") }) //nolint:errcheck

	srvConn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { srvConn.CloseWithError(0, "test done") }) //nolint:errcheck

	cliStream, err := cliConn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	srvStream, err := srvConn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	return cliStream, srvStream
}

// newStaleAgentClient builds a real *control.Client connected to a real
// staleAgentServer over an in-memory stream pair.
func newStaleAgentClient(t *testing.T) *control.Client {
	t.Helper()
	cliStream, srvStream := pairControlStreams(t, "routes-stale")

	gs := grpc.NewServer()
	controlpb.RegisterControlServer(gs, staleAgentServer{})
	ln := control.NewSingleConnListener(control.NewConn(srvStream))
	go gs.Serve(ln) //nolint:errcheck
	t.Cleanup(gs.Stop)

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// TestRoutesJSON_UnimplementedAgent_NamesTheStaleVersion proves that a real
// codes.Unimplemented reply from a real (simulated-old) agent, reaching
// routesProvider's real production mapping code through a real
// *control.Client, is turned into its own specific message naming the
// version mismatch — never the raw gRPC error string.
func TestRoutesJSON_UnimplementedAgent_NamesTheStaleVersion(t *testing.T) {
	t.Parallel()
	staleClient := newStaleAgentClient(t)

	pool := &fakeRoutesPool{
		state: "connected",
		controlFn: func(ctx context.Context, fn func(context.Context, *control.Client) error) error {
			return fn(ctx, staleClient)
		},
	}
	provider := daemon.NewRoutesProvider(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := provider.RoutesJSON(ctx, "srv")
	if err == nil {
		t.Fatal("RoutesJSON succeeded against a real stale (pre-GetStatus) agent")
	}
	var re *ipc.RoutesError
	if !errors.As(err, &re) {
		t.Fatalf("RoutesJSON error is not *ipc.RoutesError: %v", err)
	}
	const want = `the agent at server "srv" is running a version that does not report its routes; rebuild both ends`
	if re.Msg != want {
		t.Errorf("Msg = %q, want %q", re.Msg, want)
	}
	if re.Status != 3 {
		t.Errorf("Status = %d, want 3", re.Status)
	}
	lower := strings.ToLower(re.Msg)
	if strings.Contains(lower, "unimplemented") || strings.Contains(lower, "rpc error") {
		t.Errorf("Msg leaks the raw gRPC error text: %q", re.Msg)
	}
}
