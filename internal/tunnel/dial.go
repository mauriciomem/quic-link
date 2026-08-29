package tunnel

import (
	"context"
	"log/slog"
	"time"

	"github.com/mauriciomem/quic-link/internal/backoff"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// bothDialHintAfter is how many consecutive failures pass before the retry log
// stops assuming the peer is merely down and raises the other possibility.
// Both ends configured to connect out looks exactly like an unreachable peer
// from either side, so nothing can tell them apart automatically; all this side
// can do is mention it once the count is high enough that "not started yet" has
// stopped being the likely answer.
const bothDialHintAfter = 20

// Clock is the small slice of time this loop needs, so a test can drive
// reconnect timing without waiting on a real one.
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	After(d time.Duration) <-chan time.Time
}

// WallClock is the real implementation.
type WallClock struct{}

func (WallClock) Now() time.Time                         { return time.Now() }
func (WallClock) Since(t time.Time) time.Duration        { return time.Since(t) }
func (WallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// DialAndServe connects out to addr and serves the connection, reconnecting for
// as long as ctx lives. It is the agent's side of a tunnel where the client
// waits rather than connects.
//
// Everything about serving is shared with the accepting path: the peer identity
// comes from the connection's certificate and the route table is enforced the
// same way, because none of that depends on who opened the transport. What is
// specific to this direction is the loop around it, since whichever end opens
// the connection is the end that has to reopen it.
//
// It returns when ctx ends, or when the peer rejects our identity, or when the
// peer is using our own identity — both are configuration problems that will
// not fix themselves by retrying.
func DialAndServe(
	ctx context.Context,
	t transport.Transport,
	addr string,
	rtr *router.Router,
	policy backoff.Policy,
	clock Clock,
	opts ...ServeOpts,
) error {
	var opt ServeOpts
	if len(opts) > 0 {
		opt = opts[0]
	}

	attempt := 0
	consecutiveFails := 0
	var lastSuccessAt time.Time

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		conn, err := t.Dial(ctx, addr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if transport.IsAuthFailed(err) {
				// The client does not accept our identity. Retrying cannot
				// change that, and doing so forever would bury the one message
				// that says what is actually wrong.
				slog.Error("client rejected our identity; giving up",
					"role", "agent", "addr", addr, "err", err)
				return err
			}

			if transport.IsRoleMismatch(err) {
				// Both ends are configured with the same key, so retrying
				// cannot resolve it either — it needs a separate key for one
				// end, not another attempt.
				slog.Error("client is using our own identity; giving up. "+
					"Both ends are configured with the same key, so neither can tell which role the "+
					"other is playing: generate a separate key for each end",
					"role", "agent", "addr", addr, "err", err)
				return err
			}

			consecutiveFails++
			d := policy.Backoff(attempt)
			attempt++

			if consecutiveFails == bothDialHintAfter {
				slog.Warn("still cannot reach the client; "+
					"if the client is also configured to connect out, neither end is waiting for the other — "+
					"exactly one end must be the one that waits",
					"role", "agent", "addr", addr,
					"consecutive_fails", consecutiveFails,
				)
			}
			slog.Warn("client unreachable; retrying",
				"role", "agent",
				"addr", addr,
				"attempt", attempt,
				"next_retry_in", d,
				"consecutive_fails", consecutiveFails,
				"err", err,
			)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-clock.After(d):
			}
			continue
		}

		if lastSuccessAt.IsZero() {
			slog.Info("connected to client", "role", "agent", "addr", addr)
		} else {
			slog.Info("reconnected to client", "role", "agent", "addr", addr)
		}
		consecutiveFails = 0
		attempt = 0
		lastSuccessAt = clock.Now()

		// Serve until the connection is gone. This is the same handling the
		// accepting path uses, unchanged.
		ServeConn(ctx, conn, rtr, opt)

		if ctx.Err() != nil {
			return ctx.Err()
		}

		// A client that rejects our identity does so after our own handshake
		// has already completed, so the rejection arrives as the reason the
		// connection closed rather than as a dial error.
		cause := context.Cause(conn.Context())
		if transport.IsAuthFailed(cause) {
			slog.Error("client rejected our identity; giving up",
				"role", "agent", "addr", addr, "err", cause)
			return cause
		}

		// A role collision (both ends holding the same key) surfaces here
		// once both handshakes have already completed, rather than as a dial
		// error. It cannot self-heal by retrying, so it is terminal exactly
		// like the auth-failure case above.
		if transport.IsRoleMismatch(cause) {
			slog.Error("client is using our own identity; giving up. "+
				"Both ends are configured with the same key, so neither can tell which role the "+
				"other is playing: generate a separate key for each end",
				"role", "agent", "addr", addr, "err", cause)
			return cause
		}

		// A session that stayed up long enough starts the schedule over, so a
		// stable link that drops once does not inherit a long wait from an
		// outage hours earlier. Decided before the backoff below consults
		// attempt so the block stays correct by construction even if the
		// post-connect "attempt = 0" above (which already makes attempt 0
		// here on every ordinary path) is ever removed or reordered — not
		// because a stale value is reachable today.
		if clock.Since(lastSuccessAt) > policy.StableAfter() {
			attempt = 0
		}

		d := policy.Backoff(attempt)
		attempt++

		slog.Warn("client connection lost; reconnecting",
			"role", "agent",
			"addr", addr,
			"attempt", attempt,
			"next_retry_in", d,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-clock.After(d):
		}
	}
}
