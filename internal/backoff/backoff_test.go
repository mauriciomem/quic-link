package backoff_test

import (
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/backoff"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// The reconnect schedule is specified as full-jitter exponential backoff with
// base 250ms, factor 2, cap 15s, and a reset after 60s of stable uptime. Full
// jitter means the wait is drawn uniformly from zero up to the capped
// exponential ceiling, rather than being the ceiling itself. These tests pin
// both halves: that the ceiling is computed as specified, and that the value
// actually returned is a draw below it rather than a fixed number.

// testPolicy returns a policy with the production parameters and an injected
// draw sequence, so a test can assert exact values instead of only a range.
func testPolicy(draws ...float64) backoff.Exponential {
	i := 0
	return backoff.Exponential{
		Base:         250 * time.Millisecond,
		Factor:       2,
		Cap:          15 * time.Second,
		StableAfter_: 60 * time.Second,
		Rand: func() float64 {
			d := draws[i%len(draws)]
			i++
			return d
		},
	}
}

// TestBackoff_DrawScalesTheCeiling asserts the exact full-jitter arithmetic
// against a known draw sequence: the returned wait is draw * ceiling, where
// ceiling is the capped exponential.
func TestBackoff_DrawScalesTheCeiling(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		draw    float64
		want    time.Duration
	}{
		{"attempt 0, draw 0 → no wait at all", 0, 0.0, 0},
		{"attempt 0, draw 0.5 → half of 250ms", 0, 0.5, 125 * time.Millisecond},
		{"attempt 0, draw 1 → the full 250ms ceiling", 0, 1.0, 250 * time.Millisecond},
		{"attempt 1, draw 0.5 → half of 500ms", 1, 0.5, 250 * time.Millisecond},
		{"attempt 3, draw 0.25 → a quarter of 2s", 3, 0.25, 500 * time.Millisecond},
		{"attempt 6, draw 1 → the full 15s ceiling (16s capped)", 6, 1.0, 15 * time.Second},
		{"attempt 20, draw 0.5 → half the cap, not half of 2^20", 20, 0.5, 7500 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := testPolicy(tt.draw).Backoff(tt.attempt)
			if got != tt.want {
				t.Errorf("Backoff(%d) with draw %v = %v, want %v",
					tt.attempt, tt.draw, got, tt.want)
			}
		})
	}
}

// TestBackoff_SuccessiveValuesDiffer is the direct non-determinism assertion,
// and it runs against the real production policy rather than an injected stub:
// a range check alone would pass against a jitter-free implementation, which is
// exactly the assertion shape this test exists to avoid.
func TestBackoff_SuccessiveValuesDiffer(t *testing.T) {
	p := backoff.Default()

	const draws = 50
	seen := make(map[time.Duration]struct{}, draws)
	for i := 0; i < draws; i++ {
		seen[p.Backoff(5)] = struct{}{}
	}

	if len(seen) < 2 {
		t.Errorf("Backoff(5) returned %d distinct value(s) across %d calls: %v — "+
			"the wait is not being randomised", len(seen), draws, seen)
	}
}

// TestBackoff_StaysWithinCeiling asserts the bound holds for every draw the
// real generator can produce, including at attempt numbers large enough to
// overflow the exponential to infinity.
//
// Kept for its bounds and overflow coverage only. It is deliberately NOT
// evidence of jitter: an identical bounds check passed against the jitter-free
// implementation this policy replaced.
func TestBackoff_StaysWithinCeiling(t *testing.T) {
	p := backoff.Default()
	ceilings := []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		1000 * time.Millisecond,
	}
	for attempt, ceiling := range ceilings {
		for i := 0; i < 200; i++ {
			got := p.Backoff(attempt)
			if got < 0 || got > ceiling {
				t.Fatalf("Backoff(%d) = %v, outside [0, %v]", attempt, got, ceiling)
			}
		}
	}

	for _, attempt := range []int{40, 100, 1000, 100000} {
		got := p.Backoff(attempt)
		if got < 0 || got > 15*time.Second {
			t.Errorf("Backoff(%d) = %v, outside [0, 15s]", attempt, got)
		}
	}

	if got := p.Backoff(-1); got < 0 || got > 250*time.Millisecond {
		t.Errorf("Backoff(-1) = %v, outside [0, 250ms]", got)
	}
}

// TestDefault_ParametersUnchanged pins the four specified parameters. Adding
// jitter must not perturb base, factor, cap, or the stable reset; this test is
// what makes that claim checkable rather than asserted.
func TestDefault_ParametersUnchanged(t *testing.T) {
	p, ok := backoff.Default().(backoff.Exponential)
	if !ok {
		t.Fatalf("Default() is %T, want Exponential", backoff.Default())
	}
	if p.Base != 250*time.Millisecond {
		t.Errorf("Base = %v, want 250ms", p.Base)
	}
	if p.Factor != 2 {
		t.Errorf("Factor = %v, want 2", p.Factor)
	}
	if p.Cap != 15*time.Second {
		t.Errorf("Cap = %v, want 15s", p.Cap)
	}
	if p.StableAfter() != 60*time.Second {
		t.Errorf("StableAfter() = %v, want 60s", p.StableAfter())
	}

	// Default must apply jitter, so repeated calls for the same attempt must
	// not all return the same wait: every client retrying in lockstep is what
	// jitter exists to prevent. Twenty draws is far more than needed to see
	// variation from a working generator, and it lets the failure say which
	// property broke rather than only that two calls matched.
	const draws = 20
	seen := make(map[time.Duration]struct{}, draws)
	for i := 0; i < draws; i++ {
		seen[p.Backoff(4)] = struct{}{}
	}
	if len(seen) == 1 {
		for d := range seen {
			t.Errorf("Default returned %v on all %d draws for attempt 4; jitter is not wired up", d, draws)
		}
	}
}

// TestExponential_JitterScalesTheCeiling pins the arithmetic the previous
// check could only infer. With the draw fixed, the wait is exactly the drawn
// fraction of the ceiling, so a change to either the ceiling or the way the
// draw is applied fails here with the numbers in the message.
func TestExponential_JitterScalesTheCeiling(t *testing.T) {
	p := backoff.Exponential{
		Base:   250 * time.Millisecond,
		Factor: 2,
		Cap:    15 * time.Second,
		Rand:   func() float64 { return 0.5 },
	}
	// attempt 4 -> 250ms * 2^4 = 4s, uncapped; half of it is 2s.
	if got, want := p.Backoff(4), 2*time.Second; got != want {
		t.Errorf("Backoff(4) with a fixed 0.5 draw = %v, want %v (half of the 4s ceiling)", got, want)
	}
	// A high attempt clamps to Cap first, so half of 15s is 7.5s.
	if got, want := p.Backoff(30), 7500*time.Millisecond; got != want {
		t.Errorf("Backoff(30) with a fixed 0.5 draw = %v, want %v (half of the 15s cap)", got, want)
	}
}
