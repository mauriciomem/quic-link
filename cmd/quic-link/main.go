// Command quic-link is a minimal QUIC tunnel with mutual Ed25519 pin
// authentication. Choose a role with a subcommand:
//
//	quic-link keygen   -- generate an Ed25519 identity and print its pin
//	quic-link agent    -- QUIC agent; forwards streams to local services
//	quic-link daemon   -- session owner; manages QUIC sessions and the local socket
//	quic-link ping     -- measures handshake time and RTT to an agent
//	quic-link stdio    -- (hidden) single-stream stdio bridge
//
// "serve" is accepted as a deprecated alias for "agent".
// "connect" is accepted as a deprecated alias for "daemon --server NAME".
//
// Authentication is mutual raw-public-key pinning: each end holds an Ed25519
// key (quic-link keygen), exchanges pins out of band, and verifies the peer's
// pin during the TLS handshake. There are no CA files.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// alreadyReportedErr is the interface implemented by errors that were already
// communicated to the user (e.g. the agent's refusal message written to
// stderr). main() skips the generic slog.Error line for these to avoid a
// confusing double message.
type alreadyReportedErr interface {
	alreadyReported() bool
}

// forcedExitTimeout is the upper bound on how long the process waits for a
// graceful drain after the first SIGINT or SIGTERM before calling os.Exit(1)
// unconditionally. It is the backstop for cases where the drain itself hangs
// — e.g. goroutines parked in futex_wait that never unblock — rather than a
// target for normal shutdown (which completes in well under a second). The
// value must be long enough that it never fires during healthy shutdown on a
// slow or heavily loaded host, yet short enough that an operator who sends one
// signal gets a response without resorting to SIGKILL.
//
// Normal graceful drain: ~0.25 s. Design bounded drain: ~3–5 s.
// This constant is set to 30 s: 6× the design ceiling, so transient OS
// scheduling hiccups on a loaded host cannot trigger it during a healthy
// shutdown, while still bounding the worst-case hang at something a human
// notices before walking away.
const forcedExitTimeout = 30 * time.Second

// handleSignals watches sigCh for SIGINT/SIGTERM and enforces a hard-exit
// deadline. The timeout parameter controls how long to wait after the first
// signal before forcing exit; main() passes forcedExitTimeout, tests pass a
// short value.
//
// Behaviour:
//   - First signal: cancel the root context (graceful drain begins) and arm a
//     watchdog timer. exitFn(1) is called when the timer fires.
//   - Second signal before the timer fires: exitFn(1) is called immediately.
//   - Channel closed before any signal (normal process exit): return cleanly
//     without calling exitFn.
//
// exitFn is called at most once regardless of which path fires first. Only
// main() passes os.Exit as exitFn; tests pass a recording stub.
func handleSignals(cancel context.CancelFunc, sigCh <-chan os.Signal, exitFn func(int), timeout time.Duration) {
	sig, ok := <-sigCh
	if !ok {
		return // channel closed before any signal — normal exit path
	}
	slog.Info("signal received; starting graceful shutdown", "signal", sig)
	cancel()

	// exitOnce ensures the watchdog and the second-signal path cannot both
	// call exitFn: the real os.Exit terminates the process so double-call is
	// only observable in tests, where it would send to an already-full channel
	// or panic. Once eliminates the ambiguity on both paths.
	var exitOnce sync.Once
	forceExit := func(reason string) {
		exitOnce.Do(func() {
			slog.Info(reason)
			exitFn(1)
		})
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case _, ok := <-sigCh:
		if ok {
			forceExit("second signal received; forcing immediate exit")
		}
		// Channel closed: main() returned normally; watchdog no longer needed.
	case <-timer.C:
		forceExit("graceful shutdown timed out; forcing exit")
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Buffer 2 so that a rapid double-signal is never dropped before the
	// handler reads it.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go handleSignals(cancel, sigCh, os.Exit, forcedExitTimeout)

	err := executeRoot(ctx, os.Args[1:])

	// context.Canceled means the user pressed Ctrl-C (or SIGTERM arrived).
	// Treat that as a clean exit — no error log, exit 0.
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}

	// If the error was already reported to stderr at the point of failure
	// (e.g. a remote-refusal status message written verbatim), skip the
	// generic log line so the operator doesn't see a confusing double message.
	var ar alreadyReportedErr
	if !errors.As(err, &ar) || !ar.alreadyReported() {
		slog.Error("fatal error", "err", err)
	}
	os.Exit(exitCodeForError(err))
}
