package control

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// Client is a gRPC Control client bound to a single control stream. Close tears
// down the gRPC binding (it does not close the underlying stream — the caller
// owns the stream's lifetime).
type Client struct {
	controlpb.ControlClient
	cc *grpc.ClientConn
}

// Close releases the gRPC client resources.
func (c *Client) Close() error { return c.cc.Close() }

// Establish forces the underlying HTTP/2 connection up (gRPC dials lazily) by
// issuing one Ping, and confirms the RPC path works.
func (c *Client) Establish(ctx context.Context) error {
	_, err := c.Ping(ctx, &controlpb.PingRequest{Nonce: time.Now().UnixNano()})
	return err
}

// PingRTT issues one Ping and returns the client-measured application
// round-trip time. RTT is measured purely on the client (send to receive); the
// agent's clock in the reply is not used (cross-host skew makes it unsafe).
func (c *Client) PingRTT(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	_, err := c.Ping(ctx, &controlpb.PingRequest{Nonce: start.UnixNano()})
	return time.Since(start), err
}

// NewClient builds a Control client that speaks gRPC over the given control
// stream. The stream MUST already be past its header/response handshake (the
// remaining bytes are the HTTP/2 byte stream). TLS is provided by the QUIC
// layer, so the gRPC transport itself is insecure.
func NewClient(stream transport.Stream) (*Client, error) {
	conn := NewConn(stream)
	used := false
	dialer := func(context.Context, string) (net.Conn, error) {
		if used {
			// The stream is single-use; a fresh session opens a new stream and
			// a new Client. Refusing a re-dial surfaces session death cleanly.
			return nil, fmt.Errorf("control: dialer may only be used once")
		}
		used = true
		return conn, nil
	}
	cc, err := grpc.NewClient(
		"passthrough:///control",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("control: new grpc client: %w", err)
	}
	return &Client{ControlClient: controlpb.NewControlClient(cc), cc: cc}, nil
}
