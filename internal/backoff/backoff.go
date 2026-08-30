// Package backoff provides the reconnect schedule shared by both sides of a
// tunnel. Whichever endpoint dials owns reconnection, and that is the client
// in forward mode and the agent in reverse mode, so the policy cannot live in
// either side's own package without one of them importing the other.
package backoff

import (
	"math"
	"math/rand/v2"
	"time"
)

// Policy controls the timing of reconnect attempts after a session drops.
// It is an interface so tests can drive reconnect sequences without waiting on
// a real clock.
type Policy interface {
	// Backoff returns the duration to wait before attempt number n (0-indexed).
	Backoff(n int) time.Duration
	// StableAfter returns how long a session must stay up before it counts as
	// stable, which resets the attempt counter on the next drop.
	StableAfter() time.Duration
}

// Exponential is the production policy: full-jitter exponential backoff. Base
// multiplied by Factor each attempt gives a ceiling, capped at Cap, and the
// actual wait is drawn uniformly from zero up to that ceiling. After
// StableFor of connected uptime the attempt counter resets.
//
// The jitter is the point, not a refinement. Without it every client that lost
// the same agent retries in lockstep, so each retry round arrives as a
// synchronised burst and the recovering peer is hit hardest exactly when it is
// least able to cope. Spreading each client's wait across the whole interval
// flattens those bursts. This is the algorithm published as "full jitter" in
// AWS's Exponential Backoff And Jitter article; the two nearby variants, equal
// jitter and decorrelated jitter, spread differently and are not what is
// specified here.
type Exponential struct {
	Base      time.Duration
	Factor    float64
	Cap       time.Duration
	StableFor time.Duration

	// Rand draws the jitter fraction, in [0,1). Leave it nil in production:
	// nil means the shared generator from the standard library, which is
	// seeded automatically and safe to call from several session goroutines
	// at once. Tests set it to assert an exact sequence rather than a range.
	Rand func() float64
}

// Backoff returns the wait duration before attempt n (0-indexed).
func (p Exponential) Backoff(n int) time.Duration {
	if n < 0 {
		n = 0
	}
	// Ceiling first. A large n overflows the exponential to +Inf, which
	// compares greater than Cap and so is clamped like any other overshoot;
	// that keeps a long outage from producing a nonsense duration.
	ceiling := float64(p.Base) * math.Pow(p.Factor, float64(n))
	if ceiling > float64(p.Cap) {
		ceiling = float64(p.Cap)
	}

	draw := p.Rand
	if draw == nil {
		draw = rand.Float64
	}
	return time.Duration(draw() * ceiling)
}

// StableAfter returns the uptime after which the backoff counter resets on drop.
func (p Exponential) StableAfter() time.Duration {
	return p.StableFor
}

// Default returns the project-standard reconnect schedule: 250ms base, x2
// factor, 15s cap, reset after 60s of stable uptime.
func Default() Policy {
	return Exponential{
		Base:      250 * time.Millisecond,
		Factor:    2,
		Cap:       15 * time.Second,
		StableFor: 60 * time.Second,
	}
}
