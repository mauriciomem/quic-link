// Command quic-link is a minimal QUIC tunnel with mutual Ed25519 pin
// authentication. Choose a role with a subcommand:
//
//	quic-link keygen   -- generate an Ed25519 identity and print its pin
//	quic-link agent    -- QUIC agent; forwards streams to local services
//	quic-link connect  -- QUIC client; exposes the tunnel as local TCP ports
//	quic-link ping     -- measures handshake time and RTT to an agent
//	quic-link stdio    -- (hidden) single-stream stdio bridge
//
// "serve" is accepted as a deprecated alias for "agent".
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
	"syscall"
)

// alreadyReportedErr is the interface implemented by errors that were already
// communicated to the user (e.g. the agent's refusal message written to
// stderr). main() skips the generic slog.Error line for these to avoid a
// confusing double message.
type alreadyReportedErr interface {
	alreadyReported() bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
