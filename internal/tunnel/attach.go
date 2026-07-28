package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// StreamConn is the minimal surface DoAttach needs: an already-established,
// already-authenticated connection on which it opens exactly one stream. It
// never dials. Both a real transport.Conn and the daemon's pooled conn satisfy
// it — the daemon's Conn interface includes OpenStream specifically so the
// attach path can use this interface without importing internal/transport.
type StreamConn interface {
	OpenStream(ctx context.Context) (transport.Stream, error)
}

// ResetConn resets a connection leg abruptly so callers outside this package
// (e.g. the IPC and edge error paths) can tear down the local side of a splice
// consistently using the same semantics as the tunnel's internal resetConn.
func ResetConn(c io.Closer) {
	resetConn(c)
}

// DoAttach opens one stream on conn, sends a protocol header naming the logical
// target, waits for the agent's response (exactly one header and one response
// before any payload, as the protocol requires), optionally relays the ack to
// the local leg via relayAck, and on success bidirectionally splices
// local↔stream with full half-close semantics. It never dials.
//
// relayAck is called with the agent's response before splicing begins. It may
// be nil when the caller needs no ack (e.g. the edge accept-loop path, which
// behaves identically to the direct local-port forwardTCP). On a non-zero
// status the stream is reset and the local leg is torn down.
//
// reqid is stamped into the header's Meta for cross-host log correlation.
func DoAttach(ctx context.Context, conn StreamConn, local io.ReadWriteCloser, target, reqid string, relayAck func(proto.Response) error) error {
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		// The pooled conn dropped since Get returned — surface the error so the
		// caller can decide whether to retry or fail. Never retry/invalidate here;
		// the pool owns reconnect.
		return fmt.Errorf("open stream for %q: %w", target, err)
	}

	hdr := proto.Header{
		Kind:   proto.KindTCP,
		Target: target,
		Meta:   map[string]string{"reqid": reqid},
	}
	if err := proto.WriteHeader(stream, hdr); err != nil {
		stream.Reset(proto.StreamResetCode)
		resetConn(local)
		return fmt.Errorf("write header for %q: %w", target, err)
	}

	// Wait for the agent's response before sending any payload — the protocol
	// requires exactly one header frame and one response frame before the data
	// phase begins. pipelining is not supported.
	resp, err := awaitResponse(ctx, stream, proto.ResponseDeadline)
	if err != nil {
		// awaitResponse already reset the stream on error.
		resetConn(local)
		return fmt.Errorf("await response for %q: %w", target, err)
	}

	// Relay the ack to the local leg before deciding whether to splice. The
	// relay MUST happen before pipe() so the local client gets an answer while
	// the connection is still in the ack-relay state, not mid-splice.
	if relayAck != nil {
		if err := relayAck(resp); err != nil {
			stream.Reset(proto.StreamResetCode)
			resetConn(local)
			return fmt.Errorf("relay ack for %q: %w", target, err)
		}
	}

	if resp.Status != proto.StatusOK {
		stream.Reset(proto.StreamResetCode)
		resetConn(local)
		return fmt.Errorf("agent refused %q: status %s: %s", target, resp.Status, resp.Msg)
	}

	// pipe closes both local and stream when done. It propagates half-close
	// (FIN→FIN) and abrupt close (error→reset) faithfully in both directions.
	pipe(local, stream)
	return nil
}

// OpenControl opens the control gRPC stream on an already-dialed conn,
// classifying an auth rejection that surfaces after the local handshake
// completes. Under QUIC+TLS 1.3 the client's own handshake finishes before the
// agent's pin check completes, so a rejection can arrive on the control-open
// error OR on the connection's close cause — both paths are checked. This
// helper is the single location for that classification logic so it is not
// duplicated between connect and the daemon pool.
func OpenControl(ctx context.Context, conn transport.Conn, version string, opts control.OpenOpts) (*control.Client, error) {
	cclient, err := control.Open(ctx, conn, version, opts)
	if err != nil {
		// Check the control-open error first, then the connection's close cause.
		// The agent can reject our pin by closing the connection with a TLS alert
		// after our own handshake has already succeeded.
		if authErr := transport.AuthError(err); authErr != nil {
			return nil, authErr
		}
		if authErr := transport.AuthError(context.Cause(conn.Context())); authErr != nil {
			return nil, authErr
		}
		return nil, err
	}
	return cclient, nil
}

// attachReadyTimeout is the maximum time DoAttach waits for the pool to
// provide a live connection. A session that is still connecting will make the
// caller wait up to this long before returning a "not ready" error. Five
// seconds is long enough to cover a single-flight reconnect in progress but
// short enough to give the operator a fast failure when the agent is genuinely
// down.
const attachReadyTimeout = 5 * time.Second

// LogAttach emits the open/close audit pair for a splice. Both the ipc server
// and the edge accept loops call this so the audit lines are structurally
// identical regardless of how the attach was initiated.
func LogAttach(server, target, reqid, pinPrefix string, start time.Time, closing bool) {
	if closing {
		slog.Info("attach closed",
			"role", "daemon",
			"reqid", reqid,
			"server", server,
			"target", target,
			"peer", pinPrefix,
			"duration", time.Since(start).Round(time.Millisecond),
		)
		return
	}
	slog.Info("attach opened",
		"role", "daemon",
		"reqid", reqid,
		"server", server,
		"target", target,
		"peer", pinPrefix,
	)
}
