package probe
// Package probe implements the quic-link ping subcommand.
package probe

import (
	"context"
	"fmt"
	"time"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// Result holds timing measurements from a single QUIC handshake probe.
//
// RTT terminology follows RFC 9002 §5 (QUIC Loss Detection and Congestion
// Control):
//
//	- latest_rtt  (§5.1): most recent RTT sample from an ACK-bearing packet.
//	- min_rtt     (§5.2): minimum RTT observed — a lower bound on one-way delay.
//	- smoothed_rtt(§5.3): EWMA of RTT samples; the primary metric for
//	                      retransmission and PTO calculation.
type Result struct {
	// HandshakeTime is the wall-clock time from Dial to HandshakeComplete.
	// It includes one full round-trip (Initial + Handshake) and TLS processing.
	HandshakeTime time.Duration
	// SmoothedRTT is the EWMA RTT after the handshake (RFC 9002 §5.3).
	SmoothedRTT time.Duration
	// MinRTT is the minimum RTT observed during the connection (RFC 9002 §5.2).
	MinRTT time.Duration
	// LatestRTT is the most recent RTT sample (RFC 9002 §5.1).
	LatestRTT time.Duration
}

// Ping establishes a QUIC connection to serverAddr, waits for the handshake
// to complete, reads RTT statistics, and returns the measurements.
// The caller is responsible for closing the Transport after Ping returns.
func Ping(ctx context.Context, t transport.Transport, serverAddr string) (*Result, error) {
	start := time.Now()
	conn, err := t.Dial(ctx, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("ping dial: %w", err)
	}
	defer conn.CloseWithError(0, "ping done") //nolint:errcheck

	// Block until 1-RTT keys are derived: only then do RTT estimates reflect
	// actual network conditions rather than the initial 333 ms estimate.
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	elapsed := time.Since(start)
	stats := conn.Stats()

	return &Result{
		HandshakeTime: elapsed,
		SmoothedRTT:   stats.SmoothedRTT,
		MinRTT:        stats.MinRTT,
		LatestRTT:     stats.LatestRTT,
	}, nil
}
