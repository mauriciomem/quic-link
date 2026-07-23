package control

import (
	"context"
	"fmt"
	"time"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// OpenOpts carries optional parameters for Open. All fields are optional;
// the zero value is valid and produces the same behaviour as the original
// two-parameter call.
type OpenOpts struct {
	// KeyCreated is an RFC3339 UTC string recording when the client's identity
	// key was generated. When non-empty it is included in the control-stream
	// header so the agent can log a rotation reminder for over-age client keys.
	// The field is self-asserted and advisory only — the agent must never use
	// it to gate or close a session.
	KeyCreated string
}

// Open establishes the session's control stream against an established QUIC
// connection: it opens a stream, performs the protocol-v1 header/response
// handshake (kind "control", meta proto:"1"), builds a gRPC Control client over
// the post-response bytes, and eagerly brings the HTTP/2 connection up with one
// Ping (so the agent's transport is live and does not sit waiting for a
// preface). version is advertised in the header meta. opts carries optional
// per-session metadata; pass zero value if not needed.
//
// On any failure the stream is reset and a non-nil error is returned; the
// caller should treat the session as unusable.
func Open(ctx context.Context, conn transport.Conn, version string, opts OpenOpts) (*Client, error) {
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("control: open stream: %w", err)
	}

	meta := map[string]string{"proto": "1", "version": version}
	if opts.KeyCreated != "" {
		meta["key_created"] = opts.KeyCreated
	}
	h := proto.Header{
		Kind: proto.KindControl,
		Meta: meta,
	}
	if err := proto.WriteHeader(stream, h); err != nil {
		stream.Reset(proto.StreamResetCode)
		return nil, fmt.Errorf("control: write header: %w", err)
	}

	resp, err := readResponse(ctx, stream, proto.ResponseDeadline)
	if err != nil {
		return nil, fmt.Errorf("control: await response: %w", err)
	}
	if resp.Status != proto.StatusOK {
		stream.Reset(proto.StreamResetCode)
		return nil, fmt.Errorf("control: agent refused stream: status=%d %s", uint(resp.Status), resp.Msg)
	}

	client, err := NewClient(stream)
	if err != nil {
		stream.Reset(proto.StreamResetCode)
		return nil, err
	}

	// Bring the HTTP/2 connection up eagerly (gRPC dials lazily) and confirm
	// the RPC path works.
	establishCtx, cancel := context.WithTimeout(ctx, proto.ResponseDeadline)
	defer cancel()
	if err := client.Establish(establishCtx); err != nil {
		_ = client.Close()
		stream.Reset(proto.StreamResetCode)
		return nil, fmt.Errorf("control: establish: %w", err)
	}
	return client, nil
}

// readResponse reads a single response frame from stream, bounded by d and ctx.
// On timeout or cancellation the stream is reset (which unblocks the reader).
func readResponse(ctx context.Context, stream transport.Stream, d time.Duration) (proto.Response, error) {
	type result struct {
		resp proto.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := proto.ReadResponse(stream)
		ch <- result{resp, err}
	}()

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case res := <-ch:
		if res.err != nil {
			stream.Reset(proto.StreamResetCode)
			return proto.Response{}, res.err
		}
		return res.resp, nil
	case <-timer.C:
		stream.Reset(proto.StreamResetCode)
		return proto.Response{}, fmt.Errorf("timed out after %s waiting for control response", d)
	case <-ctx.Done():
		stream.Reset(proto.StreamResetCode)
		return proto.Response{}, ctx.Err()
	}
}
