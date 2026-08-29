package ipc_test

// server_test.go covers concurrent-access behavior of Server that the
// per-method test files (routes_test.go, oversized_test.go, etc.) don't
// exercise: what happens when a provider setter (SetRoutes, SetVhosts,
// SetDoctor, SetExpose, SetWithdraw) is called while Serve is already
// running and handling requests concurrently.
//
// @spec-handoff
//
// Interface under test: (*ipc.Server).SetRoutes and the "routes" case in
// handleRPC, as a stand-in for all five Set* setters and their matching
// read sites — they share the same shape (an unguarded field write paired
// with an unguarded field read).
//
// Expected behavior: calling a Set* method concurrently with Serve handling
// requests that read the same field must not race. The race detector must
// report zero data races for this scenario once the fix lands.
//
// Edge case exercised here: the setter is called AFTER Serve has already
// started accepting connections (not before, which is the documented and
// exercised-elsewhere usage). This is deliberately the undocumented,
// enforcement-free path that a caller could take today with no compiler or
// runtime signal that it's wrong.
//
// Pre-fix failure mode: `go test -race` reports a DATA RACE between the
// write in SetRoutes and the read of s.routes in handleRPC's "routes" case.
// This test's job is to force that interleaving reliably enough for `-race`
// to catch it, not to assert a specific outcome value — the race itself is
// the defect.

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// TestSetRoutes_ConcurrentWithServe_NoRace drives a goroutine calling
// SetRoutes in a loop against a goroutine repeatedly issuing "routes" IPC
// requests through an already-serving Server, so that a write of s.routes
// and a read of s.routes can interleave. Under `go test -race` this must
// report no data race after the fix. Before the fix, the race detector
// flags the unsynchronized write in SetRoutes against the unsynchronized
// read in handleRPC's "routes" case.
func TestSetRoutes_ConcurrentWithServe_NoRace(t *testing.T) {
	sock := shortSocketPath(t)
	srv := ipc.NewServer(sock, &stubStatus{data: []byte(`{}`)}, &stubPool{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
		os.Remove(sock)
	})

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: repeatedly calls SetRoutes with a fresh provider, well after
	// Serve has already started accepting connections.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			stub := newStubRoutes()
			stub.body = []byte(`{"schema":1,"server":"race","routes":[]}`)
			srv.SetRoutes(stub)
		}
	}()

	// Reader: repeatedly issues a "routes" RPC, which reads s.routes inside
	// handleRPC. A response error is tolerable here (the provider may be
	// mid-swap or absent momentarily) — this test asserts on the race
	// detector's output, not on any particular response content.
	go func() {
		defer wg.Done()
		c := ipc.NewClient(sock)
		for i := 0; i < iterations; i++ {
			_, _ = c.RoutesJSON("race")
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for concurrent SetRoutes/RoutesJSON to finish")
	}
}
