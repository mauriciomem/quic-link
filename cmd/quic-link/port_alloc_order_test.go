package main

// Test for the sorted-iteration invariant in the port-allocation loop.
//
// When two servers' deterministic base ports collide, the server allocated
// first (in sorted / alphabetical order) keeps the base block; the server
// allocated second steps +10. This matches the production loop in daemoncmd.go,
// which iterates serverNames in sorted order and holds each listener open for
// the daemon's lifetime. Randomised map iteration would break this: the winner
// changes run-to-run, so a user who learned that "serverX is on port N" would
// find it on a different port after a daemon restart.
//
// The two colliding names below ("beta19" and "server2") were found empirically:
//   config.LocalPortBase("beta19") == config.LocalPortBase("server2") == 53070
//
// In sorted order "beta19" < "server2", so "beta19" always wins the base block
// when listeners are acquired in that order and held open.

import (
	"fmt"
	"net"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/edge"
)

// collisionPair holds the two server names used in allocation-order tests.
// They must share the same deterministic base-port block.
const (
	collisionFirst  = "beta19"  // alphabetically first; wins the base block
	collisionSecond = "server2" // collides; must step when allocated after first
)

// TestPortAllocation_SortedFirstWinsBaseBlock verifies that when two servers
// share the same base-port block, allocating them in sorted (alphabetical)
// name order — the same order as the production loop — causes the
// alphabetically-earlier server to hold the base block and the later server to
// step. Listeners are held open during the second allocation, mirroring the
// production pattern where all listeners are held for the daemon's lifetime.
//
// The test runs the sorted allocation 20 times to confirm the outcome is fully
// deterministic, not coincidentally correct on the first attempt.
func TestPortAllocation_SortedFirstWinsBaseBlock(t *testing.T) {
	baseSSH, _ := config.LocalPorts(collisionFirst, nil)
	if b2, _ := config.LocalPorts(collisionSecond, nil); b2 != baseSSH {
		t.Skipf("collision fixture is stale: %q→%d %q→%d; update test",
			collisionFirst, baseSSH, collisionSecond, b2)
	}
	stepped := baseSSH + 10

	const runs = 20
	for i := range runs {
		alloc := edge.PortAllocator{}

		// Sorted order: allocate collisionFirst, hold its listeners, then
		// allocate collisionSecond. This mirrors the production loop.
		ln1ssh, ln1dkr, err := alloc.AcquirePair(collisionFirst, nil)
		if err != nil {
			t.Fatalf("run %d: AcquirePair(%q): %v", i, collisionFirst, err)
		}
		got1SSH := ln1ssh.Addr().(*net.TCPAddr).Port

		// Listeners for collisionFirst are still open — collisionSecond cannot
		// take those ports and must step.
		ln2ssh, ln2dkr, err := alloc.AcquirePair(collisionSecond, nil)
		if err != nil {
			ln1ssh.Close()
			ln1dkr.Close()
			t.Fatalf("run %d: AcquirePair(%q): %v", i, collisionSecond, err)
		}
		got2SSH := ln2ssh.Addr().(*net.TCPAddr).Port

		ln1ssh.Close()
		ln1dkr.Close()
		ln2ssh.Close()
		ln2dkr.Close()

		if got1SSH != baseSSH {
			t.Errorf("run %d: %q got ssh=%d, want base %d — "+
				"sorted-first server must hold the base block",
				i, collisionFirst, got1SSH, baseSSH)
		}
		if got2SSH != stepped {
			t.Errorf("run %d: %q got ssh=%d, want stepped %d — "+
				"sorted-second server must step when the base is occupied",
				i, collisionSecond, got2SSH, stepped)
		}
	}
}

// TestPortAllocation_ReversedOrderFlipsWinner documents — and tests — that
// reversed iteration assigns the base block to the wrong server. This confirms
// TestPortAllocation_SortedFirstWinsBaseBlock would catch randomised map
// iteration rather than passing by luck of ordering.
//
// With randomised map iteration, about half of daemon restarts would allocate
// in reversed order, causing "server2" to land on the base block and "beta19"
// to step — the opposite of what a user who configured those ports expects.
func TestPortAllocation_ReversedOrderFlipsWinner(t *testing.T) {
	baseSSH, _ := config.LocalPorts(collisionFirst, nil)
	if b2, _ := config.LocalPorts(collisionSecond, nil); b2 != baseSSH {
		t.Skipf("collision fixture is stale; update test")
	}
	stepped := baseSSH + 10

	alloc := edge.PortAllocator{}

	// REVERSED order: allocate collisionSecond first, hold its listeners.
	ln2ssh, ln2dkr, err := alloc.AcquirePair(collisionSecond, nil)
	if err != nil {
		t.Fatalf("AcquirePair(%q): %v", collisionSecond, err)
	}
	got2SSH := ln2ssh.Addr().(*net.TCPAddr).Port

	// collisionFirst cannot take baseSSH (held by collisionSecond) — steps.
	ln1ssh, ln1dkr, err := alloc.AcquirePair(collisionFirst, nil)
	if err != nil {
		ln2ssh.Close()
		ln2dkr.Close()
		t.Fatalf("AcquirePair(%q): %v", collisionFirst, err)
	}
	got1SSH := ln1ssh.Addr().(*net.TCPAddr).Port

	ln1ssh.Close()
	ln1dkr.Close()
	ln2ssh.Close()
	ln2dkr.Close()

	// In reversed order the winner flips: collisionSecond holds the base.
	if got2SSH != baseSSH {
		t.Errorf("reversed: %q got ssh=%d, want base %d", collisionSecond, got2SSH, baseSSH)
	}
	if got1SSH != stepped {
		t.Errorf("reversed: %q got ssh=%d, want stepped %d", collisionFirst, got1SSH, stepped)
	}
	t.Logf("confirmed: reversed allocation gives %q→%d and %q→%d; "+
		"sorted allocation gives %q→%d and %q→%d — order matters",
		collisionSecond, got2SSH, collisionFirst, got1SSH,
		collisionFirst, baseSSH, collisionSecond, stepped)
}

// Sanity-check the collision fixture at init time so a broken fixture is
// caught immediately on build, not silently skipped.
func init() {
	b1, _ := config.LocalPorts(collisionFirst, nil)
	b2, _ := config.LocalPorts(collisionSecond, nil)
	if b1 != b2 {
		panic(fmt.Sprintf("port_alloc_order_test.go: collision fixture is stale: "+
			"%q→%d %q→%d; find a new colliding pair and update the constants",
			collisionFirst, b1, collisionSecond, b2))
	}
}
