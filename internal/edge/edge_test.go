package edge_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/edge"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---- helpers ----------------------------------------------------------------

// memEdgeSetup wires an in-memory agent (tunnel.Serve) and returns the
// client-side transport.Conn as a ConnSource-compatible fake pool.
type memEdgeSetup struct {
	conn transport.Conn
}

func (s *memEdgeSetup) OpenConn(_ context.Context, _ string) (tunnel.StreamConn, string, error) {
	return s.conn, "testpeer", nil
}

func newMemEdgeSetup(t *testing.T) *memEdgeSetup {
	t.Helper()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (server): %v", err)
	}

	hub := mem.NewHub()
	srvT := hub.Transport("edge-agent:1", mem.WithCert(serverLeaf))
	cliT := hub.Transport("edge-client:1", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// Echo server for the agent's "ssh" target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEdgeEchoSrv(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go tunnel.Serve(ctx, ln, rtr) //nolint:errcheck

	conn, err := cliT.Dial(ctx, "edge-agent:1")
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "test done") }) //nolint:errcheck

	// Open control stream so the agent's 5s deadline doesn't fire.
	cclient, cerr := tunnel.OpenControl(ctx, conn, "edge-test", control.OpenOpts{})
	if cerr != nil {
		t.Logf("OpenControl: %v (may be OK for short tests)", cerr)
	} else if cclient != nil {
		t.Cleanup(func() { cclient.Close() }) //nolint:errcheck
	}

	return &memEdgeSetup{conn: conn}
}

func runEdgeEchoSrv(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n]) //nolint:errcheck
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}

// ---- PortAllocator tests ----------------------------------------------------

// TestPortAllocator_AcquirePair_HoldsListeners verifies that AcquirePair
// returns open listeners (not probed-then-closed), eliminating TOCTOU.
func TestPortAllocator_AcquirePair_HoldsListeners(t *testing.T) {
	t.Parallel()
	alloc := edge.PortAllocator{}

	sshLn, dkrLn, err := alloc.AcquirePair("testserver", nil)
	if err != nil {
		t.Fatalf("AcquirePair: %v", err)
	}
	defer sshLn.Close()
	defer dkrLn.Close()

	// Verify both listeners are actually accepting connections.
	dialAndClose := func(addr net.Addr) {
		conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
		if err != nil {
			t.Errorf("dial %s: %v", addr, err)
			return
		}
		conn.Close()
	}
	dialAndClose(sshLn.Addr())
	dialAndClose(dkrLn.Addr())
}

// TestPortAllocator_AcquirePair_StepsOnClash verifies that AcquirePair skips
// blocks where the base ports are already taken and tries the next +10 block.
func TestPortAllocator_AcquirePair_StepsOnClash(t *testing.T) {
	t.Parallel()
	alloc := edge.PortAllocator{}

	// Pre-bind the base ports for "clashserver".
	sshBase, dkrBase := config.LocalPorts("clashserver", nil)

	l1, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", sshBase))
	if err != nil {
		t.Skip("cannot bind base ssh port; skipping clash test")
	}
	defer l1.Close()
	l2, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", dkrBase))
	if err != nil {
		t.Skip("cannot bind base docker port; skipping clash test")
	}
	defer l2.Close()

	// AcquirePair must step to the next block.
	sshLn, dkrLn, err := alloc.AcquirePair("clashserver", nil)
	if err != nil {
		t.Fatalf("AcquirePair with clash: %v", err)
	}
	defer sshLn.Close()
	defer dkrLn.Close()

	gotSSH := sshLn.Addr().(*net.TCPAddr).Port
	gotDkr := dkrLn.Addr().(*net.TCPAddr).Port
	if gotSSH == sshBase || gotDkr == dkrBase {
		t.Errorf("AcquirePair did not step past the blocked base ports: ssh=%d docker=%d", gotSSH, gotDkr)
	}
}

// ---- localPortEdge tests ----------------------------------------------------

// TestLocalPortEdge_ByteExactRoundTrip verifies that a TCP connection to the
// edge's ssh port is spliced correctly through to the echo agent.
func TestLocalPortEdge_ByteExactRoundTrip(t *testing.T) {
	t.Parallel()
	src := newMemEdgeSetup(t)

	alloc := edge.PortAllocator{}
	sshLn, dkrLn, err := alloc.AcquirePair("edgeserver", nil)
	if err != nil {
		t.Fatalf("AcquirePair: %v", err)
	}
	defer dkrLn.Close() // closed by edge.Close normally

	ctx, cancel := context.WithCancel(context.Background())
	e := edge.NewLocalPortEdge(ctx, "edgeserver", sshLn, dkrLn, src)
	t.Cleanup(func() {
		cancel()
		e.Close()
	})

	// Dial the ssh edge port and check echo.
	conn, err := net.DialTimeout("tcp", sshLn.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial edge ssh port: %v", err)
	}
	defer conn.Close()

	payload := []byte("edge-echo-test")
	conn.Write(payload) //nolint:errcheck
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}
}

// TestLocalPortEdge_GolangClean verifies that edge.Close joins all goroutines
// (goleak-clean) and returns without hanging.
func TestLocalPortEdge_GolangClean(t *testing.T) {
	src := newMemEdgeSetup(t)

	alloc := edge.PortAllocator{}
	sshLn, dkrLn, err := alloc.AcquirePair("edgeserver2", nil)
	if err != nil {
		t.Fatalf("AcquirePair: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := edge.NewLocalPortEdge(ctx, "edgeserver2", sshLn, dkrLn, src)

	// Close should return promptly and not leak goroutines.
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Close()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("edge.Close did not return within 3s")
	}
}
