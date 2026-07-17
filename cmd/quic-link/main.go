// Command quic-link is a minimal QUIC SSH tunnel.
// Choose a role with a subcommand:
//
//	quic-link keygen  -- generate an Ed25519 identity and print its pin
//	quic-link serve   -- QUIC server; forwards streams to a TCP service
//	quic-link connect -- QUIC client; exposes the tunnel as a local TCP port
//	quic-link ping    -- measures handshake time and RTT to a server
//
// Authentication is mutual raw-public-key pinning: each end holds an Ed25519 key
// (quic-link keygen), exchanges pins out of band, and verifies the peer's pin
// during the TLS handshake. There are no CA files.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

const usageText = `quic-link: minimal QUIC SSH tunnel

Subcommands:
  keygen   Generate an Ed25519 identity key and print its pin.
  serve    Run the QUIC server endpoint (binds a UDP port, forwards to a TCP service).
  connect  Run the local client endpoint (listens on a local TCP port, tunnels to server).
  ping     Measure QUIC handshake time and steady-state RTT to a server.

Pairing (one time per host):
  quic-link keygen                       # each host: prints "pin: <base64>"
  # exchange the two pins out of band, then pass them to serve/connect below.

Examples:
  # Server (run on the remote machine, port 443 UDP must be reachable)
  quic-link serve \
    --listen :443 --service-addr 127.0.0.1:22 \
    --authorized-client <client-pin>

  # Client (run locally, then: ssh -p 2222 user@127.0.0.1)
  quic-link connect \
    --server myserver.example.com:443 --local 127.0.0.1:2222 \
    --pin <server-pin>

  # Ping
  quic-link ping --server myserver.example.com:443 --count 5 --pin <server-pin>
`

// errUsage marks an error as a usage/validation failure so main() exits with
// the usage-error code (2).
var errUsage = errors.New("usage error")

func usageErrorf(format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), errUsage)
}

// defaultKeyPath resolves ~/.config/quic-link/key.pem on EVERY OS. It uses
// os.UserHomeDir, NOT os.UserConfigDir (which on macOS returns
// ~/Library/Application Support) — the same ~/.config scheme is used on every
// platform.
func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "key.pem"
	}
	return filepath.Join(home, ".config", "quic-link", "key.pem")
}

// expandTilde expands a leading ~ or ~/ to the user's home directory.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// pinList collects repeatable --authorized-client flags. Each value is
// validated and normalized via identity.ParsePin as it is set.
type pinList []string

func (p *pinList) String() string { return strings.Join(*p, ",") }

func (p *pinList) Set(v string) error {
	norm, err := identity.ParsePin(v)
	if err != nil {
		return err
	}
	*p = append(*p, norm)
	return nil
}

// clientTLSFromFlags loads the Ed25519 identity key and builds the client-side
// pinning tls.Config for the expected server pin. Shared by connect and ping.
func clientTLSFromFlags(keyFile, serverPin string) (*tls.Config, error) {
	key, err := identity.LoadKey(expandTilde(keyFile))
	if err != nil {
		return nil, fmt.Errorf("load identity key: %w", err)
	}
	tlsConf, err := identity.ClientTLS(key, serverPin)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}
	return tlsConf, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "connect":
		err = runConnect(ctx, os.Args[2:])
	case "ping":
		err = runPing(ctx, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usageText)
		os.Exit(1)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("fatal error", "err", err)
		os.Exit(exitCodeForError(err))
	}
}

// exitCodeForError maps a fatal error to a process exit code:
// 2 usage error · 4 authentication/authorization failure · 1 anything else.
func exitCodeForError(err error) int {
	switch {
	case errors.Is(err, transport.ErrAuthFailed):
		return 4
	case errors.Is(err, errUsage):
		return 2
	default:
		return 1
	}
}

// runKeygen implements the keygen subcommand: create an Ed25519 identity if
// absent (idempotent — an existing key prints its pin and exits 0; --force
// rotates with a warning) and print the CONTRACT line "pin: <base64>" last.
// It also writes the "<key>.meta" creation-time sidecar. It creates only
// quic-link's own files.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	force := fs.Bool("force", false, "rotate: overwrite an existing key (peers must re-pair)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link keygen [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	keyPath := expandTilde(*out)

	_, statErr := os.Stat(keyPath)
	exists := statErr == nil

	if exists && !*force {
		// Idempotent: print the existing pin, rewrite nothing (rotation must be
		// explicit). A missing .meta is left missing — do not fabricate a time.
		key, err := identity.LoadKey(keyPath)
		if err != nil {
			return fmt.Errorf("load existing key %s: %w", keyPath, err)
		}
		pin, err := identity.PinForKey(key)
		if err != nil {
			return err
		}
		fmt.Printf("pin: %s\n", pin)
		return nil
	}

	if exists && *force {
		fmt.Fprintln(os.Stderr, "warning: rotating identity; peers must re-pair with the new pin")
	}

	key, err := identity.Generate()
	if err != nil {
		return err
	}
	if err := identity.WriteKey(keyPath, key); err != nil {
		return fmt.Errorf("write key %s: %w", keyPath, err)
	}
	if err := identity.WriteMeta(keyPath, time.Now().UTC()); err != nil {
		return fmt.Errorf("write key metadata: %w", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		return err
	}
	fmt.Printf("pin: %s\n", pin)
	return nil
}

// runServe implements the serve subcommand.
func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":443", "UDP address to listen on")
	serviceAddr := fs.String("service-addr", "127.0.0.1:22", "TCP address of the ssh service (host:port)")
	dockerAddr := fs.String("docker-addr", "unix:///var/run/docker.sock", "docker daemon address (unix:///path or tcp://host:port)")
	keyFile := fs.String("key", defaultKeyPath(), "Path to the Ed25519 identity key (PKCS#8 PEM)")
	var authorized pinList
	fs.Var(&authorized, "authorized-client", "authorized client pin (repeatable; at least one required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link serve [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	// No unauthenticated listener: an empty authorized set is a usage error.
	if len(authorized) == 0 {
		fs.Usage()
		return usageErrorf("at least one --authorized-client pin is required")
	}

	// Authentication (the pinning handshake) is enforced here; authorization
	// (the router policy) stays allow-all — two separate gates.
	key, err := identity.LoadKey(expandTilde(*keyFile))
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}
	tlsConf, err := identity.ServerTLS(key, authorized)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	rtr, err := router.New(map[string]string{
		"ssh":    "tcp://" + *serviceAddr,
		"docker": *dockerAddr,
	}, router.AllowAll{})
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return fmt.Errorf("invalid --listen address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind %s: %w", *listen, err)
	}
	defer udpConn.Close()

	t, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	defer t.Close()

	ln, err := t.Listen()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	// Log only the COUNT of authorized clients, never the pins.
	slog.Info("quic-link serve ready",
		"listen", ln.Addr(),
		"targets", rtr.Targets(),
		"authorized_clients", len(authorized),
	)
	return tunnel.Serve(ctx, ln, rtr)
}

// runConnect implements the connect subcommand.
func runConnect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	server := fs.String("server", "", "host:port of the quic-link server")
	local := fs.String("local", "127.0.0.1:2222", "local TCP address for the ssh target")
	localDocker := fs.String("local-docker", "127.0.0.1:2375", "local TCP address for the docker target")
	sshTarget := fs.String("ssh-target", "ssh", "logical target for the --local port (advanced; for manual unknown-target checks)")
	keyFile := fs.String("key", defaultKeyPath(), "Path to the Ed25519 identity key (PKCS#8 PEM)")
	pin := fs.String("pin", "", "expected server pin (base64; from `quic-link keygen` on the server)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link connect [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" {
		fs.Usage()
		return usageErrorf("--server is required")
	}
	serverPin, err := identity.ParsePin(*pin)
	if err != nil {
		fs.Usage()
		return usageErrorf("--pin is required and must be a valid pin: %v", err)
	}

	tlsConf, err := clientTLSFromFlags(*keyFile, serverPin)
	if err != nil {
		return err
	}

	// Ephemeral IPv4 UDP port for outbound QUIC (any available local port).
	// Bind udp4 rather than a dual-stack [::] socket: on macOS a dual-stack
	// socket fails to transmit IPv4-mapped datagrams to an on-link neighbor
	// (no ARP is performed), silently dropping packets to LAN peers.
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

	sshLn, err := net.Listen("tcp", *local)
	if err != nil {
		return fmt.Errorf("bind ssh port %s: %w", *local, err)
	}
	defer sshLn.Close()

	dockerLn, err := net.Listen("tcp", *localDocker)
	if err != nil {
		return fmt.Errorf("bind docker port %s: %w", *localDocker, err)
	}
	defer dockerLn.Close()

	slog.Info("quic-link connect ready",
		"ssh_local", sshLn.Addr(),
		"docker_local", dockerLn.Addr(),
		"server", *server,
	)
	forwards := []tunnel.Forward{
		{Listener: sshLn, Target: *sshTarget},
		{Listener: dockerLn, Target: "docker"},
	}
	return tunnel.Connect(ctx, t, *server, forwards)
}

// runPing implements the ping subcommand.
func runPing(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	server := fs.String("server", "", "host:port of the quic-link server")
	count := fs.Int("count", 3, "number of probes to send")
	keyFile := fs.String("key", defaultKeyPath(), "Path to the Ed25519 identity key (PKCS#8 PEM)")
	pin := fs.String("pin", "", "expected server pin (base64; from `quic-link keygen` on the server)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link ping [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" {
		fs.Usage()
		return usageErrorf("--server is required")
	}
	serverPin, err := identity.ParsePin(*pin)
	if err != nil {
		fs.Usage()
		return usageErrorf("--pin is required and must be a valid pin: %v", err)
	}

	tlsConf, err := clientTLSFromFlags(*keyFile, serverPin)
	if err != nil {
		return err
	}

	var (
		successful     int
		totalHandshake float64
		totalSmoothed  float64
		totalMin       float64
		successfulRPC  int
		totalRPC       float64
		authErr        error // set if any probe failed the pinning handshake
	)

	for i := 1; i <= *count; i++ {
		// Each probe uses a fresh QUIC connection from a new IPv4 UDP socket.
		// udp4 (not dual-stack [::]) so on-link LAN peers are reachable on macOS.
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			return fmt.Errorf("UDP socket: %w", err)
		}

		t, err := transport.NewQUICTransport(udpConn, tlsConf, nil)
		if err != nil {
			udpConn.Close()
			return fmt.Errorf("transport: %w", err)
		}

		res, err := probe.Ping(ctx, t, *server)
		t.Close()
		udpConn.Close()

		if err != nil {
			if errors.Is(err, transport.ErrAuthFailed) {
				authErr = err
			}
			fmt.Fprintf(os.Stderr, "probe %d/%d: %v\n", i, *count, err)
			continue
		}

		fmt.Printf("probe %d/%d: handshake=%v smoothed_rtt=%v min_rtt=%v latest_rtt=%v\n",
			i, *count,
			res.HandshakeTime.Round(time.Microsecond),
			res.SmoothedRTT.Round(time.Microsecond),
			res.MinRTT.Round(time.Microsecond),
			res.LatestRTT.Round(time.Microsecond),
		)
		// Application-level control-stream RPC round-trip, labeled distinctly
		// from the transport RTT. A control failure is non-fatal: the
		// transport numbers above are still meaningful.
		if res.RPCErr != nil {
			fmt.Printf("           control_rpc: FAILED (%v)\n", res.RPCErr)
		} else {
			fmt.Printf("           control_rpc_rtt=%v\n", res.RPCRoundTrip.Round(time.Microsecond))
			totalRPC += float64(res.RPCRoundTrip)
			successfulRPC++
		}
		successful++
		totalHandshake += float64(res.HandshakeTime)
		totalSmoothed += float64(res.SmoothedRTT)
		totalMin += float64(res.MinRTT)
	}

	if successful == 0 {
		// If every probe failed the pinning handshake, surface it as an auth
		// error so main() exits 4 rather than collapsing to a generic exit 1.
		if authErr != nil {
			return fmt.Errorf("all %d probes failed: %w", *count, authErr)
		}
		return fmt.Errorf("all %d probes failed", *count)
	}
	n := float64(successful)
	fmt.Printf("--- %s ping statistics ---\n", *server)
	fmt.Printf("%d probes sent, %d successful\n", *count, successful)
	fmt.Printf("avg: handshake=%v smoothed_rtt=%v min_rtt=%v\n",
		time.Duration(totalHandshake/n).Round(time.Microsecond),
		time.Duration(totalSmoothed/n).Round(time.Microsecond),
		time.Duration(totalMin/n).Round(time.Microsecond),
	)
	if successfulRPC > 0 {
		fmt.Printf("avg: control_rpc_rtt=%v (%d/%d ok)\n",
			time.Duration(totalRPC/float64(successfulRPC)).Round(time.Microsecond),
			successfulRPC, successful,
		)
	}
	return nil
}

// ---- exit-code mapping ---------------------------------------------------------

// exitCodeForStatus maps an agent response status to a process exit code:
// 0 ok · 4 auth/authz failure · 5 remote refused (unknown target, dial failed,
// draining) · 1 anything unexpected. No verb consumes it yet, but the mapping is
// a locked contract, so it lands with the codes it names.
func exitCodeForStatus(s proto.Status) int {
	switch s {
	case proto.StatusOK:
		return 0
	case proto.StatusUnauthorized:
		return 4
	case proto.StatusUnknownTarget, proto.StatusDialFailed, proto.StatusDraining:
		return 5
	default:
		return 1
	}
}
