// Package probe implements the quic-link ping subcommand.
package probe

import (
	"context"
	"fmt"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// Result holds timing measurements from a single QUIC handshake probe.
//
// RTT terminology follows RFC 9002 (QUIC Loss Detection and Congestion
// Control):
//
//   - latest_rtt: most recent RTT sample from an ACK-bearing packet.
//   - min_rtt: minimum RTT observed — a lower bound on one-way delay.
//   - smoothed_rtt: EWMA of RTT samples; the primary metric for
//     retransmission and PTO calculation.
type Result struct {
	// HandshakeTime is the wall-clock time from Dial to HandshakeComplete.
	// It includes one full round-trip (Initial + Handshake) and TLS processing.
	HandshakeTime time.Duration
	// SmoothedRTT is the EWMA RTT after the handshake (RFC 9002).
	SmoothedRTT time.Duration
	// MinRTT is the minimum RTT observed during the connection (RFC 9002).
	MinRTT time.Duration
	// LatestRTT is the most recent RTT sample (RFC 9002).
	LatestRTT time.Duration
	// RPCRoundTrip is the application-level round-trip of a control-stream
	// Ping RPC. It includes gRPC/HTTP2 encoding and agent scheduling,
	// so it is always >= the transport RTT. Zero if RPCErr is non-nil.
	RPCRoundTrip time.Duration
	// RPCErr records why the control-stream Ping failed, if it did. The
	// transport measurements are still valid when this is set.
	RPCErr error
}

// Ping establishes a QUIC connection to serverAddr, waits for the handshake to
// complete, reads transport RTT statistics, then opens the control stream and
// times a Ping RPC. The transport measurements are always returned; a
// control-stream failure is reported in Result.RPCErr rather than failing the
// whole probe. The caller is responsible for closing the Transport after Ping
// returns.
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

	res := &Result{
		HandshakeTime: elapsed,
		SmoothedRTT:   stats.SmoothedRTT,
		MinRTT:        stats.MinRTT,
		LatestRTT:     stats.LatestRTT,
	}

	// Application round-trip over the control stream. control.Open
	// already issues one establishing Ping; a second, timed Ping isolates the
	// steady-state RPC latency.
	client, err := control.Open(ctx, conn, "quic-link ping", control.OpenOpts{})
	if err != nil {
		// A pin rejected by the agent tears the connection down after our own
		// handshake completes, so it surfaces here rather than at Dial. Report
		// it as an authentication failure (so ping exits with the auth code)
		// instead of a reachable-but-broken peer. Check both the immediate
		// error and the connection's close cause.
		if authErr := transport.AuthError(err); authErr != nil {
			return nil, authErr
		}
		if authErr := transport.AuthError(context.Cause(conn.Context())); authErr != nil {
			return nil, authErr
		}
		res.RPCErr = err
		return res, nil
	}
	defer client.Close() //nolint:errcheck
	rtt, err := client.PingRTT(ctx)
	if err != nil {
		res.RPCErr = err
		return res, nil
	}
	res.RPCRoundTrip = rtt
	return res, nil
}
