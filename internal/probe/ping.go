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
	// SmoothedRTT is the EWMA RTT sampled after the control RPC (RFC 9002).
	SmoothedRTT time.Duration
	// MinRTT is the minimum RTT observed during the connection, sampled after
	// the control RPC (RFC 9002).
	MinRTT time.Duration
	// LatestRTT is the most recent RTT sample, taken after the control RPC
	// (RFC 9002).
	LatestRTT time.Duration
	// HasRTT reports whether the transport RTT fields above contain a genuine
	// network measurement. When false the fields hold a seeded placeholder and
	// must not be displayed as measurements. See the sampling note in Ping.
	HasRTT bool
	// RPCRoundTrip is the application-level round-trip of a control-stream
	// Ping RPC. It includes gRPC/HTTP2 encoding and agent scheduling,
	// so it is always >= the transport RTT. Zero if RPCErr is non-nil.
	RPCRoundTrip time.Duration
	// RPCInvariantViolation is non-nil when RPCRoundTrip < MinRTT, which is
	// physically impossible: the application round-trip cannot be shorter than
	// the network round-trip. The caller should surface this loudly. It never
	// affects the exit code.
	RPCInvariantViolation error
	// RPCErr records why the control-stream Ping failed, if it did. The
	// transport measurements are still valid when this is set. RPCErr can
	// carry proto.Response.Msg verbatim (via control.Open, on a non-OK
	// control-stream response) — text the agent that answered this probe's
	// handshake worded itself. A caller that prints RPCErr to an operator
	// terminal or log must sanitize it first; ping's own cmd/quic-link
	// renderer does.
	RPCErr error
}

// Ping establishes a QUIC connection to serverAddr, waits for the handshake to
// complete, opens the control stream, times a Ping RPC, then re-reads transport
// RTT statistics. Re-reading after the RPC means at least one genuine ACK
// sample has been taken by the time we record the numbers, which avoids
// reporting the 100 ms placeholder that the QUIC implementation seeds before
// any real measurement arrives.
//
// Whether a real measurement was taken is signalled by Result.HasRTT: it is
// true when MeanDeviation is non-zero. MeanDeviation starts at zero, is never
// set by the seed code, and becomes non-zero on the very first ACK-based
// sample. A zero MeanDeviation therefore reliably identifies the no-sample
// case regardless of path latency — including paths near 100 ms where a naive
// equality check against the seed value would incorrectly suppress real data.
//
// The transport measurements are always returned; a control-stream failure is
// reported in Result.RPCErr rather than failing the whole probe. The caller is
// responsible for closing the Transport after Ping returns.
func Ping(ctx context.Context, t transport.Transport, serverAddr string) (*Result, error) {
	start := time.Now()
	conn, err := t.Dial(ctx, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("ping dial: %w", err)
	}
	defer conn.CloseWithError(0, "ping done") //nolint:errcheck

	// Block until 1-RTT keys are derived: only then do RTT estimates reflect
	// actual network conditions rather than the seeded 100 ms placeholder
	// (quic-go's utils.DefaultInitialRTT).
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	elapsed := time.Since(start)

	res := &Result{
		HandshakeTime: elapsed,
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
		// Re-sample RTT even on a control-stream failure; any packets sent
		// during the attempt may have produced a measurement.
		sampleRTT(conn, res)
		res.RPCErr = err
		return res, nil
	}
	defer client.Close() //nolint:errcheck

	rtt, err := client.PingRTT(ctx)
	if err != nil {
		sampleRTT(conn, res)
		res.RPCErr = err
		return res, nil
	}
	res.RPCRoundTrip = rtt

	// Re-sample transport RTT after the RPC. The RPC completes an application
	// round trip, so by this point the QUIC stack has received at least one
	// ACK and has a genuine RTT measurement rather than the seeded placeholder.
	sampleRTT(conn, res)

	// Sanity check: an application-layer round trip cannot be shorter than
	// the underlying network round trip. If it is, something is wrong with our
	// measurement — most likely the transport RTT was sampled before any real
	// ACK arrived and still holds the seed value.
	if res.HasRTT && res.RPCRoundTrip > 0 && res.RPCRoundTrip < res.MinRTT {
		res.RPCInvariantViolation = fmt.Errorf(
			"control_rpc_rtt (%v) < min_rtt (%v): impossible — RPC round-trip cannot be shorter than the network RTT; transport RTT sample may be unreliable",
			res.RPCRoundTrip.Round(time.Microsecond),
			res.MinRTT.Round(time.Microsecond),
		)
	}

	return res, nil
}

// sampleRTT reads the current transport RTT statistics into res and sets
// res.HasRTT. It is called after at least one application round-trip to
// maximise the chance that a genuine ACK sample has been recorded.
//
// HasRTT is set to true when MeanDeviation is non-zero. The QUIC
// implementation seeds minRTT/smoothedRTT/latestRTT to 100 ms before any
// measurement but leaves meanDeviation at zero. The first UpdateRTT call sets
// meanDeviation to sample/2, which is non-zero for any real network path.
// Therefore MeanDeviation == 0 reliably identifies the "no real sample yet"
// state without incorrectly suppressing genuine 100 ms paths.
func sampleRTT(conn transport.Conn, res *Result) {
	stats := conn.Stats()
	res.SmoothedRTT = stats.SmoothedRTT
	res.MinRTT = stats.MinRTT
	res.LatestRTT = stats.LatestRTT
	res.HasRTT = stats.MeanDeviation != 0
}
