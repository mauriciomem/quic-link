package control

import (
	"context"
	"fmt"
	"time"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// Open establishes the session's control stream against an established QUIC
// connection: it opens a stream, performs the protocol-v1 header/response
// handshake (02 §2.4, kind "control", meta proto:"1"), builds a gRPC Control
// client over the post-response bytes, and eagerly brings the HTTP/2 connection
// up with one Ping (so the agent's transport is live and does not sit waiting
// for a preface). version is advertised in the header meta.
//
// On any failure the stream is reset and a non-nil error is returned; the
// caller should treat the session as unusable.
func Open(ctx context.Context, conn transport.Conn, version string) (*Client, error) {
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("control: open stream: %w", err)
	}

	h := proto.Header{
		Kind: proto.KindControl,
		Meta: map[string]string{"proto": "1", "version": version},
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
