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
//
// These tests assert the RELATIONSHIP between the two allocations and confirm
// the base block is free before asserting anything about it. That care is worth
// explaining, because the obvious version of this test is unreliable:
//
// Every base this allocator can produce lies in 42000-61990, and both platforms
// hand out ephemeral ports across most of that span (Linux from 32768, macOS
// from 49152), so any port named here may already be held by an unrelated
// process — including another test binary running in parallel. A test that
// simply demanded a specific number would then fail while reporting that the
// allocator had misbehaved, when in fact it had stepped past a busy port
// exactly as designed. No port range avoids this on both platforms, so these
// tests establish their own precondition and skip when it does not hold,
// rather than blaming the allocator for the machine.

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

// blockIsFree reports whether the base block and the one above it are all
// bindable right now, which is the precondition these tests need: the first
// allocation must be able to take the base, and the second must be able to take
// the next block up. It binds and releases rather than asking, because asking is
// the question the operating system will not answer.
//
// A false result is not a defect. It means something else on this machine holds
// one of those four ports at this instant.
func blockIsFree(base int) bool {
	var held []net.Listener
	defer func() {
		for _, l := range held {
			_ = l.Close()
		}
	}()
	for _, off := range []int{0, 1, 10, 11} {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", base+off))
		if err != nil {
			return false
		}
		held = append(held, l)
	}
	return true
}

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

	const runs = 20
	asserted := 0
	for i := range runs {
		// Confirm the precondition for this run. If the block is busy the
		// allocator will correctly step past it, which says nothing about
		// iteration order, so there is nothing to assert this time round.
		if !blockIsFree(baseSSH) {
			continue
		}
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

		// The invariant, as a relationship: whichever block the first server
		// took, the second must take the next one up.
		if got2SSH != got1SSH+10 {
			t.Errorf("run %d: %q got ssh=%d and %q got ssh=%d; the sorted-second "+
				"server must land exactly one ten-port block above the first (%d)",
				i, collisionFirst, got1SSH, collisionSecond, got2SSH, got1SSH+10)
		}
		// And because the base block was confirmed free immediately above, the
		// sorted-first server must be the one holding it.
		if got1SSH != baseSSH {
			t.Errorf("run %d: %q got ssh=%d, want the base block %d its name "+
				"derives — sorted-first server must hold the base block",
				i, collisionFirst, got1SSH, baseSSH)
		}
		asserted++
	}
	if asserted == 0 {
		t.Skipf("base block %d was busy for all %d attempts; nothing was asserted",
			baseSSH, runs)
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
	if !blockIsFree(baseSSH) {
		t.Skipf("base block %d is busy on this machine; the allocator would "+
			"correctly step past it, so there is no ordering to observe", baseSSH)
	}

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

	// In reversed order the winner flips: whichever server was allocated first
	// holds the base, and the other steps one block up.
	if got1SSH != got2SSH+10 {
		t.Errorf("reversed: %q got ssh=%d and %q got ssh=%d; the server allocated "+
			"second must land exactly one block above the first (%d)",
			collisionSecond, got2SSH, collisionFirst, got1SSH, got2SSH+10)
	}
	if got2SSH != baseSSH {
		t.Errorf("reversed: %q went first and got ssh=%d, want the base block %d",
			collisionSecond, got2SSH, baseSSH)
	}
	t.Logf("confirmed: reversed allocation gives %q→%d and %q→%d; "+
		"sorted allocation gives %q→%d and %q→%d — order matters",
		collisionSecond, got2SSH, collisionFirst, got1SSH,
		collisionFirst, baseSSH, collisionSecond, baseSSH+10)
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
