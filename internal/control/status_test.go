package control_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/router"
)

// realRouteSource adapts a real *router.Router to control.RouteSource — the
// same conversion internal/tunnel performs at the one boundary allowed to
// import both packages (internal/control must not import internal/router).
// Using it here means GetStatus is exercised against the real router's own
// provenance logic, not a test-only double that trivially satisfies whatever
// the test happens to check.
type realRouteSource struct {
	rtr *router.Router
}

func (s realRouteSource) RouteDetails() []control.RouteDetail {
	details := s.rtr.RouteDetails()
	out := make([]control.RouteDetail, len(details))
	for i, d := range details {
		out[i] = control.RouteDetail{Name: d.Name, Address: d.Address, Builtin: d.Builtin}
	}
	return out
}

// TestGetStatus_DenyPolicy_ReachesCallerAsPermissionDenied proves the same
// control-plane authorization check-point that guards Ping also guards
// GetStatus specifically — not a generic "some RPC is gated" assertion, but
// this exact method, called by name. Without this, a per-method carve-out
// (or a mistake wiring GetStatus outside the interceptor) would go
// unnoticed.
func TestGetStatus_DenyPolicy_ReachesCallerAsPermissionDenied(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "getstatus-deny")

	rtr, err := router.New(map[string]string{"ssh": "tcp://127.0.0.1:2222"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	deny := control.PolicyFunc(func(control.PeerIdentity, string) error {
		return errors.New("denied by test policy")
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, deny,
			control.ServeOpts{Routes: realRouteSource{rtr: rtr}})
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
	if err == nil {
		t.Fatalf("GetStatus succeeded against a deny-all policy (got %+v); "+
			"the authorization check-point was not consulted for GetStatus", resp)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetStatus error = %v, want a status carrying codes.PermissionDenied", err)
	}

	cancel()
	<-serveDone
}

// TestGetStatus_RouteProvenanceRoundTrips proves that an override's Builtin:
// false and an untouched built-in's Builtin: true both survive the full trip
// through control.RouteDetail, the proto conversion, the gRPC wire, and back
// out at the client — against a real *router.Router, not a hand-rolled
// stub.
func TestGetStatus_RouteProvenanceRoundTrips(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "getstatus-provenance")

	rtr, err := router.New(map[string]string{"ssh": "tcp://10.0.0.1:2222"}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil,
			control.ServeOpts{Routes: realRouteSource{rtr: rtr}})
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	byName := make(map[string]*controlpb.RouteInfo, len(resp.GetRoutes()))
	for _, r := range resp.GetRoutes() {
		byName[r.GetTarget()] = r
	}

	ssh, ok := byName["ssh"]
	if !ok {
		t.Fatal("GetStatus response has no \"ssh\" route")
	}
	if ssh.GetBuiltin() {
		t.Errorf("ssh route Builtin = true, want false — it was overridden by the operator")
	}
	if ssh.GetAddress() != "tcp://10.0.0.1:2222" {
		t.Errorf("ssh route Address = %q, want %q", ssh.GetAddress(), "tcp://10.0.0.1:2222")
	}

	docker, ok := byName["docker"]
	if !ok {
		t.Fatal("GetStatus response has no \"docker\" route")
	}
	if !docker.GetBuiltin() {
		t.Errorf("docker route Builtin = false, want true — nothing overrode it")
	}

	cancel()
	<-serveDone
}

// TestGetStatus_OrderingStable proves the route list arrives at the client in
// a stable, deterministic order across repeated calls against the same
// server — not merely that the underlying accessor happens to sort, but that
// nothing between the accessor and the wire (the proto conversion, the gRPC
// round trip) reorders it.
func TestGetStatus_OrderingStable(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "getstatus-ordering")

	rtr, err := router.New(map[string]string{
		"zzz-last":  "tcp://127.0.0.1:9001",
		"aaa-first": "tcp://127.0.0.1:9002",
		"mmm-mid":   "tcp://127.0.0.1:9003",
	}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil,
			control.ServeOpts{Routes: realRouteSource{rtr: rtr}})
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()

	var lastOrder []string
	for i := 0; i < 3; i++ {
		resp, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
		if err != nil {
			t.Fatalf("GetStatus call %d: %v", i, err)
		}
		names := make([]string, len(resp.GetRoutes()))
		for j, r := range resp.GetRoutes() {
			names[j] = r.GetTarget()
		}
		if !sortedStrings(names) {
			t.Fatalf("call %d: routes not sorted by name: %v", i, names)
		}
		if i > 0 && !equalStrings(names, lastOrder) {
			t.Fatalf("call %d order = %v, want the same order as call 0: %v", i, names, lastOrder)
		}
		lastOrder = names
	}

	cancel()
	<-serveDone
}

func sortedStrings(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i-1] > ss[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGetStatus_VersionAndStartedAt proves GetStatus reports the version and
// start-time values it was configured with, not zero values silently
// dropped somewhere in the handler.
func TestGetStatus_VersionAndStartedAt(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "getstatus-version")

	started := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil,
			control.ServeOpts{Version: "v0.5.2", StartedAt: started})
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.GetVersion() != "v0.5.2" {
		t.Errorf("Version = %q, want %q", resp.GetVersion(), "v0.5.2")
	}
	if resp.GetStartedUnixMs() != started.UnixMilli() {
		t.Errorf("StartedUnixMs = %d, want %d", resp.GetStartedUnixMs(), started.UnixMilli())
	}

	cancel()
	<-serveDone
}

// TestGetStatus_NoRouteSource_ReturnsEmptyRoutes proves GetStatus behaves
// against the real, unconfigured zero value of ServeOpts (no Routes
// supplied) rather than panicking or requiring every caller to pass one.
// This is a legitimate production configuration (every pre-existing call to
// Serve in this package's own authz_test.go passes none), not a fabricated
// "impossible state" — a genuinely empty route table cannot occur through a
// real *router.Router, which always seeds the two built-ins, so this is the
// only reachable "no routes" shape worth a test.
func TestGetStatus_NoRouteSource_ReturnsEmptyRoutes(t *testing.T) {
	t.Parallel()
	cliStream, srvStream := pairStreams(t, "getstatus-noroutes")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- control.Serve(ctx, srvStream, control.PeerIdentity{Pin: "peer-pin"}, nil)
	}()

	client, err := control.NewClient(cliStream)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus with no RouteSource configured: %v", err)
	}
	if len(resp.GetRoutes()) != 0 {
		t.Errorf("Routes = %v, want empty with no RouteSource configured", resp.GetRoutes())
	}

	cancel()
	<-serveDone
}
