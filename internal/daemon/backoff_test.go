package daemon_test

import (
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/backoff"
	"github.com/mauriciomem/quic-link/internal/daemon"
)

// The reconnect schedule itself lives in the shared backoff package, which owns
// its own tests. What this package still has to guarantee is that the daemon's
// exported names really are that policy and not a local reimplementation that
// could drift from it.

// TestDefaultReconnectPolicy_IsTheSharedPolicy proves the daemon's constructor
// returns the shared schedule, with the production parameters intact.
func TestDefaultReconnectPolicy_IsTheSharedPolicy(t *testing.T) {
	p, ok := daemon.DefaultReconnectPolicy().(backoff.Exponential)
	if !ok {
		t.Fatalf("DefaultReconnectPolicy() is %T, want the shared backoff.Exponential",
			daemon.DefaultReconnectPolicy())
	}
	if p.Base != 250*time.Millisecond || p.Factor != 2 ||
		p.Cap != 15*time.Second || p.StableAfter() != 60*time.Second {
		t.Errorf("shared policy parameters changed: %+v", p)
	}
}

// TestDefaultReconnectPolicy_IsJittered guards the wiring, not the arithmetic:
// if the daemon ever stopped using the shared policy and grew its own, the most
// likely regression is a schedule that lost its randomisation.
func TestDefaultReconnectPolicy_IsJittered(t *testing.T) {
	p := daemon.DefaultReconnectPolicy()
	seen := make(map[time.Duration]struct{})
	for i := 0; i < 50; i++ {
		seen[p.Backoff(5)] = struct{}{}
	}
	if len(seen) < 2 {
		t.Errorf("Backoff(5) returned %d distinct value(s) across 50 calls — "+
			"the daemon's policy is not jittered", len(seen))
	}
}

// TestExponentialReconnectPolicy_IsAnAlias fails to compile, rather than at
// runtime, if the alias is ever replaced by a distinct local type.
func TestExponentialReconnectPolicy_IsAnAlias(t *testing.T) {
	var _ daemon.ExponentialReconnectPolicy = backoff.Exponential{}
	var _ backoff.Exponential = daemon.ExponentialReconnectPolicy{}
}
