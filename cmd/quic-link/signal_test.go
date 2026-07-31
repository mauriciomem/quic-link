package main

// signal_test.go verifies the shutdown logic in handleSignals:
//
//   - First signal: cancels the root context so running verbs drain gracefully,
//     and arms a watchdog that forces exit if the drain hangs past the timeout.
//   - Second signal: calls exitFn immediately without waiting for the drain.
//   - No signal (channel closed): returns cleanly without calling exitFn.
//
// Background: signal.NotifyContext left the handler registered after the first
// signal, so subsequent SIGTERMs were swallowed. Additionally, with no watchdog
// the process could hang indefinitely if the drain itself stalled — which is the
// exact failure mode observed in production (daemon parked in futex_wait,
// surviving three SIGTERMs across 2.5 hours, recoverable only with SIGKILL).
//
// handleSignals is extracted from main() so it is directly testable. Tests pass
// a short timeout and a recording stub for exitFn; main() passes forcedExitTimeout
// and os.Exit.

import (
	"context"
	"os"
	"testing"
	"time"
)

// shortTimeout is used in all tests that exercise handleSignals. It must be
// short enough that tests complete quickly yet long enough that the goroutine
// scheduler has time to deliver the signal before the timer fires in tests
// that are checking that the watchdog does NOT fire.
const shortTimeout = 200 * time.Millisecond

// TestHandleSignals_FirstSignalCancelsContext verifies that the first signal
// cancels the context. The exit function must NOT be called on the first signal
// before the timeout elapses.
func TestHandleSignals_FirstSignalCancelsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 2)
	exitCalled := make(chan int, 1)
	exitFn := func(code int) { exitCalled <- code }

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSignals(cancel, sigCh, exitFn, shortTimeout)
	}()

	// Send one signal.
	sigCh <- os.Interrupt

	// The context must be cancelled promptly.
	select {
	case <-ctx.Done():
		// Good — first signal cancelled the context.
	case <-time.After(time.Second):
		t.Fatal("context was not cancelled after first signal within 1s")
	}

	// exitFn must NOT have been called yet (the timeout has not elapsed).
	select {
	case code := <-exitCalled:
		t.Errorf("exitFn called with code %d immediately after first signal; watchdog fired too early", code)
	default:
		// Good — no premature exit.
	}

	// Close the channel to simulate normal process exit — this cancels the
	// watchdog so it does not fire after the test returns.
	close(sigCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleSignals goroutine did not exit after channel close")
	}
}

// TestHandleSignals_SecondSignalCallsExit verifies that the second signal
// causes exitFn to be called immediately with code 1, without waiting for the
// verb to finish its graceful drain.
func TestHandleSignals_SecondSignalCallsExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	exitCalled := make(chan int, 1)
	exitFn := func(code int) { exitCalled <- code }

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSignals(cancel, sigCh, exitFn, shortTimeout)
	}()

	// First signal — cancels context.
	sigCh <- os.Interrupt

	// Wait for context cancellation before sending the second signal.
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled after first signal")
	}

	// Second signal — must trigger exitFn immediately.
	sigCh <- os.Interrupt

	select {
	case code := <-exitCalled:
		if code != 1 {
			t.Errorf("exitFn called with code %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("exitFn not called within 1s of second signal")
	}

	// handleSignals should return after calling exitFn.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleSignals goroutine did not exit after calling exitFn")
	}
}

// TestHandleSignals_ClosedChannelReturnsCleanly verifies that handleSignals
// returns without calling exitFn when the signal channel is closed before any
// signal is sent (e.g. when main() returns normally and the defer fires).
func TestHandleSignals_ClosedChannelReturnsCleanly(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	exitCalled := make(chan int, 1)
	exitFn := func(code int) { exitCalled <- code }

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSignals(cancel, sigCh, exitFn, shortTimeout)
	}()

	// Close immediately — no signal sent.
	close(sigCh)

	select {
	case <-done:
		// Good — returned without calling exitFn.
	case <-time.After(time.Second):
		t.Fatal("handleSignals did not return promptly after channel close")
	}

	select {
	case code := <-exitCalled:
		t.Errorf("exitFn called with code %d on closed channel with no signal", code)
	default:
		// Good.
	}
}

// TestHandleSignals_WatchdogFires verifies that exitFn is called after the
// timeout elapses if no second signal arrives and the process does not exit
// normally. This is the backstop for a hung graceful drain: after one
// SIGTERM, if the drain never completes, the process must not wait forever.
func TestHandleSignals_WatchdogFires(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	exitCalled := make(chan int, 1)
	exitFn := func(code int) { exitCalled <- code }

	// Use a very short timeout so the test does not wait long.
	watchdog := 50 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSignals(cancel, sigCh, exitFn, watchdog)
	}()

	// Send one signal — context cancels, watchdog arms.
	sigCh <- os.Interrupt

	// The watchdog must fire and call exitFn within a generous multiple of
	// the timeout. We do NOT close sigCh here, simulating a hung drain.
	select {
	case code := <-exitCalled:
		if code != 1 {
			t.Errorf("watchdog called exitFn with code %d, want 1", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not call exitFn within deadline (hung drain not detected)")
	}

	// handleSignals must return after calling exitFn.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleSignals goroutine did not exit after watchdog fired")
	}
}

// TestHandleSignals_WatchdogDoesNotFireOnHealthyExit verifies that exitFn is
// NOT called when the process exits normally before the watchdog fires. This
// represents the healthy case: one SIGTERM, drain completes quickly, main()
// returns and closes the channel.
func TestHandleSignals_WatchdogDoesNotFireOnHealthyExit(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	exitCalled := make(chan int, 1)
	exitFn := func(code int) { exitCalled <- code }

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSignals(cancel, sigCh, exitFn, shortTimeout)
	}()

	// Send one signal — context cancels, watchdog arms with shortTimeout.
	sigCh <- os.Interrupt

	// Simulate the drain completing quickly (well within the timeout) by
	// closing the channel. In production, main()'s defer signal.Stop fires
	// and then the channel is closed when the goroutine exits.
	time.Sleep(10 * time.Millisecond) // drain "completes" in 10ms
	close(sigCh)

	// handleSignals must return promptly after channel close.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleSignals did not return after channel close (healthy exit path)")
	}

	// exitFn must NOT have been called — the watchdog was cancelled.
	select {
	case code := <-exitCalled:
		t.Errorf("exitFn called with code %d on healthy exit; watchdog fired when it should not have", code)
	default:
		// Good.
	}
}
