package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/ipc"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
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

func newStdioCmd(a *app) *cobra.Command {
	var (
		serverFlag string
		pin        string
		keyFile    string
	)

	cmd := &cobra.Command{
		Use:    "stdio SERVER TARGET",
		Short:  "Connect a single stream to TARGET via SERVER over stdin/stdout",
		Hidden: true,
		Args:   wrapArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()

			// args[0] is the SERVER name for config resolution. args[1] is
			// the logical TARGET written into the stream header.
			serverName := args[0]
			target := args[1]

			// Resolve addr and pin from config, then let --server/--pin
			// flags override. This makes stdio work both as a standalone
			// tool (flags only) and as a ProxyCommand helper (config lookup).
			srv, ok := a.cfg.Servers[serverName]
			if !ok && !flags.Changed("server") && !flags.Changed("pin") {
				// No config entry and no flags → unresolvable.
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("server %q not found in config (and --server/--pin not provided)", serverName)
			}

			// Flag overrides always win.
			if flags.Changed("server") {
				srv.Addr = serverFlag
				srv.Listen = ""
			}
			if flags.Changed("pin") {
				srv.Pin = pin
			}

			// enabled check
			// A disabled server is not a usage error (the server name was valid);
			// it is a semantic config state meaning "this session is not available".
			// The contract is: session not available → exit 3 with a remedy message,
			// no cobra usage screen. The usage screen is reserved for flag-parse
			// errors and missing required arguments.
			if ok && srv.Enabled != nil && !*srv.Enabled {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"server %q is disabled; set enabled = true in the config to use it\n",
					serverName)
				return &errFinalExitCode{
					code: 3,
					msg:  fmt.Sprintf("server %q is disabled", serverName),
				}
			}

			effectiveKey := a.cfg.Identity.KeyFile
			if flags.Changed("key") {
				effectiveKey = keyFile
			}

			// Try the daemon socket first. If the daemon is absent, fall through to
			// the direct-QUIC path so stdio works without a running daemon.
			if sock, sockErr := daemonSocketPath(a.cfg); sockErr == nil {
				reqid := tunnel.NewReqID()
				conn, aerr := ipc.NewClient(sock).Attach(serverName, target, map[string]string{"reqid": reqid})
				switch {
				case aerr == nil:
					// Daemon attach succeeded. Splice stdin/stdout through the unix conn.
					// The conn from Attach is a *net.UnixConn which implements CloseWrite.
					tunnel.Pipe(&stdioRW{}, conn)
					return nil
				case errors.Is(aerr, ipc.ErrDaemonAbsent):
					// Daemon not running — fall through to the direct-QUIC path.
					// This fallback is a fully-authenticated fresh session: it
					// dials the agent directly using the configured server pin
					// and performs mutual Ed25519 verification itself. It is not
					// a bypass of authentication; it is the same pinning path
					// that the non-daemon connect verb uses.
				case errors.Is(aerr, ipc.ErrSchemaMismatch):
					fmt.Fprintf(os.Stderr, "quic-link: daemon socket schema mismatch; restart the daemon\n")
					return aerr
				default:
					var ae *ipc.AttachStatusError
					if errors.As(aerr, &ae) {
						// The daemon already translated the protocol status into a
						// final process exit code (stored in ae.Status). Cast it
						// back to proto.Status would re-map it through the wrong
						// table; use errFinalExitCode to carry it through unchanged.
						//
						// Choose the error prefix based on who produced the failure:
						//   exit 3 = daemon-side (session not ready, pool not
						//             connected) — no agent was ever reached.
						//   exit 4/5 = agent-side (auth rejected or target refused)
						//             — the agent responded with a non-OK status.
						// Using "agent refused" for exit 3 would send the operator
						// to the wrong host to debug — the problem is the daemon's
						// connection to the agent, not the agent itself.
						if ae.Status == 3 {
							fmt.Fprintf(os.Stderr, "%s\n", ae.Msg)
						} else {
							fmt.Fprintf(os.Stderr, "agent refused: %s\n", ae.Msg)
						}
						return &errFinalExitCode{code: ae.Status, msg: ae.Msg}
					}
					// Any other daemon error: fall through to direct dial.
				}
			}

			// Everything below dials the agent directly, which only a server
			// that has an address to dial can do. A server that waits for its
			// agent to connect has no address of its own, and its session is
			// held by the daemon, so without one there is nothing to fall back
			// to. These checks live here rather than earlier because a reverse
			// server reached through a running daemon is perfectly usable and
			// must not be refused on the way past.
			if srv.Listen != "" && srv.Addr == "" {
				return &errFinalExitCode{
					code: 3,
					msg: fmt.Sprintf("server %q waits for its agent to connect, so it has no address to dial directly; "+
						"start the daemon so it can hold the session", serverName),
				}
			}
			if srv.Addr == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("--server is required (or add SERVER to the config with an addr)")
			}
			serverPin, perr := identity.ParsePin(srv.Pin)
			if perr != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return usageErrorf("pin is required and must be a valid pin: %v", perr)
			}

			return stdioRun(cmd.Context(), srv.Addr, target, effectiveKey, serverPin)
		},
	}

	cmd.Flags().StringVar(&serverFlag, "server", "", "host:port of the quic-link agent (overrides config)")
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

	// The agent requires one control stream per session and closes the session
	// if none arrives within its open deadline, so open it before the data
	// stream and hold it for the connection's lifetime. Its closure on return
	// signals the end of this one-stream session.
	// tunnel.OpenControl (not control.Open directly) is used here so this
	// direct-QUIC path classifies an auth rejection identically to ping and
	// the daemon pool: it checks both the control-open error and the
	// connection's close cause for a TLS-alert-range rejection and maps it to
	// transport.ErrAuthFailed, which exitCodeForError turns into exit 4
	// instead of the generic exit 1.
	keyCreated := readKeyCreatedRFC3339(expandTilde(keyFile))
	cclient, err := tunnel.OpenControl(ctx, conn, "quic-link stdio", control.OpenOpts{KeyCreated: keyCreated})
	if err != nil {
		_ = conn.CloseWithError(0x03, "control open failed")
		return fmt.Errorf("control: %w", err)
	}
	defer cclient.Close()

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
