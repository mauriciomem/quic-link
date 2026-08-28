package daemon

// @spec-handoff
//
// Interface under test: (*listenEntry).failWaiters(err error) and
// (*listenEntry).Get(ctx context.Context) (Conn, error), both unexported, so
// this file lives in package daemon rather than daemon_test (precedent:
// probe_text_test.go, path_vocabulary_test.go).
//
// Behavior specified:
//   - failWaiters(err) is the mechanism SessionEntry.Close uses to unblock
//     every goroutine currently parked inside Get while a shutdown is in
//     progress (see the promise documented on the SessionEntry interface in
//     daemon.go: Close "unblocks any pending Get callers"). A caller blocked
//     in Get at the moment failWaiters(err) runs on another goroutine must
//     return promptly — not merely "wake up", but return with an error that
//     demonstrably carries err, checkable with errors.Is(gotErr, err).
//   - "Demonstrably carries" is the load-bearing requirement here. Before this
//     fix, failWaiters closed and replaced the wait channel but threw the
//     error away, so a woken Get looped, saw no live connection yet, and
//     blocked again — it could only ever return via its own ctx.Done(), which
//     is a context.DeadlineExceeded-shaped error that would satisfy a weaker
//     assertion like "err != nil" even though the real defect is still
//     present. That is why this test asserts errors.Is against a distinct
//     sentinel rather than a bare non-nil check: a test that only checked
//     "an error occurred" would pass against the unfixed code and prove
//     nothing about the discarded cause.
//
// Edge cases considered:
//   - Get must not return before failWaiters actually runs. The test proves
//     ordering with testing/synctest instead of a real-time sleep: it starts
//     Get in a bubble goroutine, calls synctest.Wait() to block until that
//     goroutine is durably parked on its select (the only way it can be
//     durably blocked, since ctx's real deadline is set far in the future and
//     is therefore not itself due), and only then calls failWaiters. This
//     also means the test needs no wall-clock timeout of its own: if the fix
//     regresses, the goroutine leaks blocked forever inside the bubble and
//     synctest's own deadlock detection panics the test — there is no need to
//     race a real timer against a real sleep.
//   - There was, before this change, no test anywhere in the package that
//     called Get concurrently with failWaiters/Close (confirmed by grep for
//     "failWaiters" across every _test.go file, which returned nothing) —
//     that gap is exactly why a green -race suite never caught this.

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

// TestListenEntry_Get_WakesWithFailWaitersCauseNotContextDeadline reproduces,
// as a committed regression test, the defect Yui root-caused with a
// throwaway sleep-based probe: failWaiters closed and replaced the wait
// channel but discarded its error argument, so a waiter that woke from it had
// nothing to read and went straight back to sleep, leaving ctx.Done() as the
// only way Get could ever return.
func TestListenEntry_Get_WakesWithFailWaitersCauseNotContextDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// A listenEntry can be constructed directly as a struct literal for a
		// focused unit test: Get and failWaiters only touch e.mu, e.current
		// and e.waiting, none of which require the accept loop or a real
		// transport to be running.
		e := &listenEntry{name: "probe", waiting: make(chan struct{})}

		// The context's own deadline is set far past anything this test does,
		// so the ONLY way Get can return is via failWaiters — if it instead
		// returns via ctx.Done(), that already proves the defect (the woken
		// goroutine looped back onto the replaced, still-open channel instead
		// of consulting a recorded cause).
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()

		type result struct {
			err error
		}
		resultCh := make(chan result, 1)
		go func() {
			_, err := e.Get(ctx)
			resultCh <- result{err: err}
		}()

		// Block until the goroutine above is durably parked on its select —
		// the channel receive is the only durably-blocking operation it can
		// reach with no connection installed and a deadline an hour away.
		synctest.Wait()

		shutdownCause := errors.New("probe shutdown cause")
		e.failWaiters(shutdownCause)

		res := <-resultCh
		if !errors.Is(res.err, shutdownCause) {
			t.Fatalf("Get returned %v after failWaiters; want an error satisfying "+
				"errors.Is(err, shutdownCause) — Get woke but discarded the shutdown cause, "+
				"which is exactly the defect this test exists to catch", res.err)
		}
	})
}
