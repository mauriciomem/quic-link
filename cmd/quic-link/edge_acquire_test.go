package main

// edge_acquire_test.go pins one rule about starting up: a server whose local
// port block is unusable is skipped, never fatal. The daemon holds sessions to
// several servers at once, and losing the ability to bind two convenience ports
// for one of them is not a reason to take the other servers offline.
//
// The behaviour is real today but was never tested, which is the kind of thing
// that gets quietly reversed by a later refactor that "tidies up" an ignored
// error.

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/edge"
)

// failFor is an allocator that fails for exactly the named servers and defers
// to the real allocator for the rest, so the successful path in the test is the
// production path and not a stand-in for it.
type failFor struct {
	names map[string]bool
	real  edge.PortAllocator
}

func (f failFor) AcquirePair(server string, overrides map[string]int) (net.Listener, net.Listener, error) {
	if f.names[server] {
		return nil, nil, errors.New("no free port pair (simulated)")
	}
	return f.real.AcquirePair(server, overrides)
}

func cfgWithServers(names ...string) *config.Config {
	c := &config.Config{Servers: map[string]config.Server{}}
	for _, n := range names {
		c.Servers[n] = config.Server{Addr: "example:7443", Pin: "x"}
	}
	return c
}

func closeAll(lns map[string][2]net.Listener) {
	for _, pair := range lns {
		pair[0].Close()
		pair[1].Close()
	}
}

// TestAcquireEdgeListeners_OneServerFails_OthersStillBound is the core claim:
// a failure for one server removes only that server's entry.
func TestAcquireEdgeListeners_OneServerFails_OthersStillBound(t *testing.T) {
	cfg := cfgWithServers("alpha", "bravo", "charlie")
	alloc := failFor{names: map[string]bool{"bravo": true}}

	ports, lns := acquireEdgeListeners(cfg, alloc)
	defer closeAll(lns)

	if _, ok := ports["bravo"]; ok {
		t.Error("the failing server must have no bound ports")
	}
	if _, ok := lns["bravo"]; ok {
		t.Error("the failing server must have no listeners")
	}
	for _, name := range []string{"alpha", "charlie"} {
		p, ok := ports[name]
		if !ok {
			t.Errorf("%s must still be bound when another server fails", name)
			continue
		}
		if p[0] == 0 || p[1] == 0 || p[0] == p[1] {
			t.Errorf("%s: implausible port pair %v", name, p)
		}
		if _, ok := lns[name]; !ok {
			t.Errorf("%s must still have listeners", name)
		}
	}
}

// TestAcquireEdgeListeners_AllServersFail_ReturnsEmptyNotPanic pins that a
// total failure is still not fatal. The daemon goes on to build its pool and
// serve its socket with no local ports at all, which is degraded but running.
func TestAcquireEdgeListeners_AllServersFail_ReturnsEmptyNotPanic(t *testing.T) {
	cfg := cfgWithServers("alpha", "bravo")
	alloc := failFor{names: map[string]bool{"alpha": true, "bravo": true}}

	ports, lns := acquireEdgeListeners(cfg, alloc)
	defer closeAll(lns)

	if len(ports) != 0 || len(lns) != 0 {
		t.Fatalf("want nothing bound, got ports=%v listeners=%d", ports, len(lns))
	}
}

// TestAcquireEdgeListeners_DisabledServerIsSkipped pins that a disabled server
// never consumes a port, so disabling one frees its block for a neighbour.
func TestAcquireEdgeListeners_DisabledServerIsSkipped(t *testing.T) {
	no := false
	cfg := cfgWithServers("alpha")
	cfg.Servers["off"] = config.Server{Addr: "example:7443", Pin: "x", Enabled: &no}

	ports, lns := acquireEdgeListeners(cfg, edge.PortAllocator{})
	defer closeAll(lns)

	if _, ok := ports["off"]; ok {
		t.Error("a disabled server must not be allocated ports")
	}
	if _, ok := ports["alpha"]; !ok {
		t.Error("an enabled server must be allocated ports")
	}
}

// TestAcquireEdgeListeners_RealAllocatorFailsWhenBlockIsFull is the guard
// against the tests above proving something about a fiction. It occupies every
// port the real allocator would try for one server, then shows the real
// allocator genuinely fails there — so the skip path is reachable in
// production, not only through an injected error.
//
// The allocator walks ten blocks, stepping ten ports at a time, and needs both
// ports of a block free. Taking the first port of each block is therefore
// enough to exhaust it.
func TestAcquireEdgeListeners_RealAllocatorFailsWhenBlockIsFull(t *testing.T) {
	const victim = "blocked"
	base, _ := config.LocalPorts(victim, nil)

	var squatters []net.Listener
	defer func() {
		for _, l := range squatters {
			l.Close()
		}
	}()
	for i := range 10 {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", base+i*10))
		if err != nil {
			t.Skipf("cannot occupy port %d in this environment: %v", base+i*10, err)
		}
		squatters = append(squatters, l)
	}

	cfg := cfgWithServers(victim, "healthy")
	ports, lns := acquireEdgeListeners(cfg, edge.PortAllocator{})
	defer closeAll(lns)

	if _, ok := ports[victim]; ok {
		t.Errorf("the real allocator was expected to fail for %q with its whole block taken", victim)
	}
	if _, ok := ports["healthy"]; !ok {
		t.Error("the other server must still be bound")
	}
}
