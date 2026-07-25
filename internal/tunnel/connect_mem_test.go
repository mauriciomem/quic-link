package tunnel

// White-box tests for connManager using the in-memory transport harness.
// These run with no UDP, no QUIC, and no OS privileges, making them
// fast and deterministic. They exercise: eager Establish, drop-monitor,
// lazy re-dial after drop, single-flight coalescing, and exit-code paths.

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// memSetup is the common test harness for connManager tests.
// It wires a fake agent (tunnel.Serve) over an in-memory transport hub with
// real identities, returning a ready-to-use connManager and cleanup.
type memSetup struct {
	hub        *mem.Hub
	clientT    transport.Transport
	serverAddr string
	rtr        *router.Router
}

// newMemSetup creates identities, starts a fake agent via tunnel.Serve,
// and returns the harness. The agent context is tied to t's cleanup.
func newMemSetup(t *testing.T) *memSetup {
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
	srvAddr := "agent:1"
	srvT := hub.Transport(srvAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("client:1", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	// A minimal router with a dummy tcp target keeps the agent happy.
	// We don't need real traffic to flow; we only need the control stream.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoSrv(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go Serve(ctx, ln, rtr) //nolint:errcheck

	return &memSetup{
		hub:        hub,
		clientT:    cliT,
		serverAddr: srvAddr,
		rtr:        rtr,
	}
}

func runEchoSrv(ln net.Listener) {
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

// TestConnManager_Establish_LiveConn verifies that Establish successfully dials
// the agent, opens the control stream, and records a live conn.
func TestConnManager_Establish_LiveConn(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{
		t:          s.clientT,
		serverAddr: s.serverAddr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if conn == nil {
		t.Fatal("Establish returned nil conn")
	}

	mgr.mu.Lock()
	current := mgr.current
	mgr.mu.Unlock()
	if current == nil {
		t.Fatal("m.current is nil after Establish")
	}
	if current != conn {
		t.Fatal("m.current differs from the conn returned by Establish")
	}
	_ = conn.CloseWithError(0, "test done")
}

// TestConnManager_DropMonitor_NilsCurrentOnClose verifies that after
// CloseWithError on the established conn, the drop-monitor nils m.current
// so the next get() triggers a re-dial.
func TestConnManager_DropMonitor_NilsCurrentOnClose(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{
		t:          s.clientT,
		serverAddr: s.serverAddr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	// Force-close the connection to simulate a drop.
	_ = conn.CloseWithError(0, "simulated drop")

	// Poll until the drop-monitor nils m.current (it runs in a goroutine).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		current := mgr.current
		mgr.mu.Unlock()
		if current == nil {
			return // drop-monitor fired correctly
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("m.current was not nilled after conn.CloseWithError (drop-monitor did not fire)")
}

// TestConnManager_Get_ReDialsAfterDrop verifies that after a conn drop,
// a subsequent get() establishes a new connection.
func TestConnManager_Get_ReDialsAfterDrop(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{
		t:          s.clientT,
		serverAddr: s.serverAddr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Establish the first connection.
	conn1, err := mgr.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	// Force a drop.
	_ = conn1.CloseWithError(0, "drop")

	// Wait for the drop-monitor.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		cur := mgr.current
		mgr.mu.Unlock()
		if cur == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// get() should re-dial and return a new conn.
	conn2, err := mgr.get(ctx)
	if err != nil {
		t.Fatalf("get after drop: %v", err)
	}
	if conn2 == nil {
		t.Fatal("get returned nil conn after drop")
	}
	if conn2 == conn1 {
		t.Fatal("get returned the same (dropped) conn — re-dial did not happen")
	}
	_ = conn2.CloseWithError(0, "done")
}

// TestConnManager_Get_SingleFlight verifies that concurrent get() callers
// while a dial is in progress all coalesce onto the same in-flight dial.
func TestConnManager_Get_SingleFlight(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	mgr := &connManager{
		t:          s.clientT,
		serverAddr: s.serverAddr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const concurrency = 8
	conns := make([]transport.Conn, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = mgr.get(ctx)
		}(i)
	}
	wg.Wait()

	// All callers must succeed with the same conn.
	var ref transport.Conn
	for i := range concurrency {
		if errs[i] != nil {
			t.Errorf("get[%d]: %v", i, errs[i])
			continue
		}
		if ref == nil {
			ref = conns[i]
		} else if conns[i] != ref {
			t.Errorf("get[%d] returned a different conn — single-flight broken", i)
		}
	}
	if ref != nil {
		_ = ref.CloseWithError(0, "done")
	}
}

// TestConnect_ErrUnreachable verifies that tunnel.Connect returns
// transport.ErrUnreachable when the server address is not registered in the hub.
func TestConnect_ErrUnreachable(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	// No listener registered at "nowhere:0".
	cliT := hub.Transport("client:eof")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Bind a local listener so Connect has something to forward.
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	defer localLn.Close()

	err = Connect(ctx, cliT, "nowhere:0", []Forward{{Listener: localLn, Target: "ssh"}})
	if !errors.Is(err, transport.ErrUnreachable) {
		t.Fatalf("expected ErrUnreachable, got: %v", err)
	}
}

// TestConnect_ErrAuthFailed verifies that tunnel.Connect returns
// transport.ErrAuthFailed when FailDial is configured to inject that error.
func TestConnect_ErrAuthFailed(t *testing.T) {
	t.Parallel()
	hub := mem.NewHub()
	// Register a server so the address resolves, but the client transport
	// is configured to always return ErrAuthFailed.
	srvT := hub.Transport("server:auth")
	srvLn, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvLn.Close()

	cliT := hub.Transport("client:auth", mem.FailDial(transport.ErrAuthFailed))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	defer localLn.Close()

	err = Connect(ctx, cliT, "server:auth", []Forward{{Listener: localLn, Target: "ssh"}})
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got: %v", err)
	}
}

// TestConnect_Healthy verifies an end-to-end byte-exact exchange through a
// mem-backed tunnel.Connect + tunnel.Serve: client connects to the agent,
// opens a local TCP listener, dials through it, and receives an echo.
func TestConnect_Healthy(t *testing.T) {
	t.Parallel()
	s := newMemSetup(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	// Connect closes localLn when ctx cancels; also close in cleanup.
	t.Cleanup(func() { localLn.Close() })

	connectDone := make(chan error, 1)
	go func() {
		connectDone <- Connect(ctx, s.clientT, s.serverAddr, []Forward{
			{Listener: localLn, Target: "ssh"},
		})
	}()

	// Dial through the local tunnel port and verify echo.
	var tcpConn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tcpConn, err = net.DialTimeout("tcp", localLn.Addr().String(), 500*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if tcpConn == nil {
		t.Fatalf("could not dial through tunnel: %v", err)
	}
	defer tcpConn.Close()

	payload := []byte("hello-mem-tunnel")
	if _, err := tcpConn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(payload))
	tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tcpConn.Read(got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}

	// Tear down by cancelling the context.
	cancel()
	select {
	case err := <-connectDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Connect returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return after ctx cancel")
	}
}
