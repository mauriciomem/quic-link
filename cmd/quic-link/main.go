// Command quic-link is a minimal QUIC SSH tunnel.
// Choose a role with a subcommand:
//
//	quic-link serve   -- QUIC server; forwards streams to a TCP service
//	quic-link connect -- QUIC client; exposes the tunnel as a local TCP port
//	quic-link ping    -- measures handshake time and RTT to a server
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mauriciomem/quic-link/internal/probe"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

const usageText = `quic-link: minimal QUIC SSH tunnel

Subcommands:
  serve    Run the QUIC server endpoint (binds a UDP port, forwards to a TCP service).
  connect  Run the local client endpoint (listens on a local TCP port, tunnels to server).
  ping     Measure QUIC handshake time and steady-state RTT to a server.

Examples:
  # Server (run on the remote machine, port 443 UDP must be reachable)
  quic-link serve \
    --listen :443 --service-addr 127.0.0.1:22 \
    --cert server.crt --key server.key --client-ca ca.crt

  # Client (run locally, then: ssh -p 2222 user@127.0.0.1)
  quic-link connect \
    --server myserver.example.com:443 --local 127.0.0.1:2222 \
    --cert client.crt --key client.key --server-ca ca.crt

  # Ping
  quic-link ping --server myserver.example.com:443 --count 5 \
    --cert client.crt --key client.key --server-ca ca.crt
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
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
		os.Exit(1)
	}
}

// runServe implements the serve subcommand.
func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":443", "UDP address to listen on")
	serviceAddr := fs.String("service-addr", "127.0.0.1:22", "TCP address of the upstream service")
	certFile := fs.String("cert", "", "Path to server TLS certificate (PEM)")
	keyFile := fs.String("key", "", "Path to server TLS private key (PEM)")
	clientCA := fs.String("client-ca", "", "Path to CA certificate used to verify client certs (PEM)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link serve [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" || *clientCA == "" {
		fs.Usage()
		return fmt.Errorf("--cert, --key, and --client-ca are all required")
	}

	tlsConf, err := buildServerTLS(*certFile, *keyFile, *clientCA)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
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

	slog.Info("quic-link serve ready", "listen", ln.Addr(), "service", *serviceAddr)
	return tunnel.Serve(ctx, ln, *serviceAddr)
}

// runConnect implements the connect subcommand.
func runConnect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	server := fs.String("server", "", "host:port of the quic-link server")
	local := fs.String("local", "127.0.0.1:2222", "local TCP address to expose")
	certFile := fs.String("cert", "", "Path to client TLS certificate (PEM)")
	keyFile := fs.String("key", "", "Path to client TLS private key (PEM)")
	serverCA := fs.String("server-ca", "", "Path to CA certificate used to verify the server (PEM)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link connect [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *certFile == "" || *keyFile == "" || *serverCA == "" {
		fs.Usage()
		return fmt.Errorf("--server, --cert, --key, and --server-ca are all required")
	}

	tlsConf, err := buildClientTLS(*certFile, *keyFile, *serverCA, *server)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
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

	localLn, err := net.Listen("tcp", *local)
	if err != nil {
		return fmt.Errorf("local listen %s: %w", *local, err)
	}
	defer localLn.Close()

	slog.Info("quic-link connect ready",
		"local", localLn.Addr(),
		"server", *server,
	)
	return tunnel.Connect(ctx, t, *server, localLn)
}

// runPing implements the ping subcommand.
func runPing(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	server := fs.String("server", "", "host:port of the quic-link server")
	count := fs.Int("count", 3, "number of probes to send")
	certFile := fs.String("cert", "", "Path to client TLS certificate (PEM)")
	keyFile := fs.String("key", "", "Path to client TLS private key (PEM)")
	serverCA := fs.String("server-ca", "", "Path to CA certificate used to verify the server (PEM)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link ping [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *certFile == "" || *keyFile == "" || *serverCA == "" {
		fs.Usage()
		return fmt.Errorf("--server, --cert, --key, and --server-ca are all required")
	}

	tlsConf, err := buildClientTLS(*certFile, *keyFile, *serverCA, *server)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	var (
		successful     int
		totalHandshake float64
		totalSmoothed  float64
		totalMin       float64
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
		successful++
		totalHandshake += float64(res.HandshakeTime)
		totalSmoothed += float64(res.SmoothedRTT)
		totalMin += float64(res.MinRTT)
	}

	if successful == 0 {
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
	return nil
}

// ---- TLS helpers ---------------------------------------------------------------

// buildServerTLS creates a tls.Config for the server side:
// presents a certificate, requires and verifies the client certificate.
func buildServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	caPool, err := loadCertPool(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load client CA: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS enforced
		NextProtos:   []string{transport.ALPN},
	}, nil
}

// buildClientTLS creates a tls.Config for the client side:
// presents a certificate, verifies the server certificate against serverCAFile.
func buildClientTLS(certFile, keyFile, serverCAFile, serverAddr string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPool, err := loadCertPool(serverCAFile)
	if err != nil {
		return nil, fmt.Errorf("load server CA: %w", err)
	}
	// Extract the hostname for SNI; fall back to the full addr if parsing fails.
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   host, // SNI + peer certificate verification
		NextProtos:   []string{transport.ALPN},
	}, nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates in %s", caFile)
	}
	return pool, nil
}
