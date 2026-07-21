package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
	"github.com/spf13/cobra"
)

// Ensure stdioRW satisfies the interfaces tunnel.Pipe expects at compile time.
// Pipe needs Read, Write, Close (io.ReadWriteCloser) and CloseWrite (so half-
// close propagates rather than resetting the connection).
var _ interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	CloseWrite() error
} = (*stdioRW)(nil)

func newStdioCmd() *cobra.Command {
	var (
		server  string
		pin     string
		keyFile string
	)

	cmd := &cobra.Command{
		Use:    "stdio SERVER TARGET",
		Short:  "Connect a single stream to TARGET via SERVER over stdin/stdout",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// args[0] is the SERVER name (accepted for future config resolution;
			// currently --server is the actual dial address). args[1] is the
			// logical TARGET written into the stream header.
			target := args[1]

			if server == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("--server is required")
			}
			serverPin, err := identity.ParsePin(pin)
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("--pin is required and must be a valid pin: %v", err)
			}
			return stdioRun(cmd.Context(), server, target, keyFile, serverPin)
		},
	}

	cmd.Flags().StringVar(&server, "server", "", "host:port of the quic-link agent (required until config resolves SERVER)")
	cmd.Flags().StringVar(&pin, "pin", "", "expected agent pin (base64; from `quic-link keygen` on the agent)")
	cmd.Flags().StringVar(&keyFile, "key", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")

	return cmd
}

// stdioRun implements the stdio verb: dial the agent, open one stream to
// target, and splice os.Stdin/os.Stdout through it. All diagnostics go to
// stderr; ONLY the tunnelled bytes are written to stdout so ssh/scp byte
// streams are not corrupted.
func stdioRun(ctx context.Context, server, target, keyFile, serverPin string) error {
	tlsConf, err := clientTLSFromFlags(keyFile, serverPin)
	if err != nil {
		return err
	}

	// Bind a udp4 (not dual-stack [::]) socket. On macOS a dual-stack socket
	// silently fails to transmit to on-link IPv4 LAN neighbors because no ARP
	// is performed.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("UDP socket: %w", err)
	}
	defer udpConn.Close()

	t, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer t.Close()

	conn, err := t.Dial(ctx, server)
	if err != nil {
		return fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.CloseWithError(0, "stdio done")

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	reqid := tunnel.NewReqID()
	hdr := proto.Header{
		Kind:   proto.KindTCP,
		Target: target,
		Meta:   map[string]string{"reqid": reqid},
	}
	if err := proto.WriteHeader(stream, hdr); err != nil {
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("write header: %w", err)
	}

	resp, err := tunnel.AwaitResponse(ctx, stream, proto.ResponseDeadline)
	if err != nil {
		return fmt.Errorf("await response: %w", err)
	}

	if resp.Status != proto.StatusOK {
		// Write the agent's refusal message verbatim to stderr so the operator
		// can read it (stdout carries only tunnelled bytes and must stay clean).
		fmt.Fprintf(os.Stderr, "agent refused: %s\n", resp.Msg)
		stream.Reset(proto.StreamResetCode)
		// Return a statusError so main() exits with the right code without
		// emitting an additional slog.Error line (the message is already above).
		return &statusError{status: resp.Status, msg: resp.Msg}
	}

	// Splice stdin/stdout through the stream. The stdioRW adapter implements
	// io.ReadWriteCloser and CloseWrite() so tunnel.Pipe's half-close logic
	// works correctly: stdin EOF → CloseWrite on the stream (FIN), stream FIN
	// → close stdout. Only tunnelled bytes reach stdout.
	tunnel.Pipe(&stdioRW{}, stream)
	return nil
}

// stdioRW adapts os.Stdin (read) and os.Stdout (write) to io.ReadWriteCloser
// for use with tunnel.Pipe. It also implements CloseWrite() so that when the
// remote stream signals EOF, tunnel.Pipe calls CloseWrite on this side to close
// stdout cleanly rather than issuing a full reset, keeping the stdin direction
// open until all data has drained.
//
// STDOUT DISCIPLINE: only Write() touches stdout. Read(), CloseWrite(), and
// Close() do not write to stdout. Nothing else in the stdio path may write to
// stdout — a stray diagnostic byte would corrupt the ssh/scp byte stream.
type stdioRW struct{}

func (s *stdioRW) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (s *stdioRW) Write(p []byte) (int, error) { return os.Stdout.Write(p) }

// Close closes both stdin and stdout when the pipe is fully done.
func (s *stdioRW) Close() error {
	_ = os.Stdin.Close()
	_ = os.Stdout.Close()
	return nil
}

// CloseWrite signals to the remote end that we have no more data to send.
// For stdio, the "write direction" is stdout → network, so we close stdout.
// The QUIC stream's FIN (sent when the stream side closes) is handled by
// tunnel.Pipe on the stream argument; here we only manage our own half.
func (s *stdioRW) CloseWrite() error {
	return os.Stdout.Close()
}
