package daemon_test

// pool_singleflight_test.go — Port 3: single-flight dial coalescing.
// Replaces internal/tunnel/connect_mem_test.go's TestConnManager_Get_SingleFlight
// (deleted along with connManager). dialEntry.Get() has a coalescing branch —
// a caller that finds no current conn but a dial already in flight blocks on
// the shared dialDone channel rather than triggering its own dial — but no
// daemon-side test exercised it: every previous Get() call in this suite
// happens AFTER the entry reaches "connected", never while dialing==true.
//
// gatedDialTransport (precedent: dialCountingTransport / dial9FailTransport /
// resetTestTransport in pool_liveness_test.go) holds the one in-flight Dial
// call open on a channel the test releases explicitly. This gives a
// deterministic window in which N concurrent Get() calls must coalesce,
// without racing a real timing window.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// gatedDialTransport blocks every Dial call on gate until the test closes it,
// counting how many Dial calls were actually made. This is the injection
// seam that lets the test observe the exact moment a dial is in-flight
// without racing a real timing window.
type gatedDialTransport struct {
	inner     transport.Transport
	gate      chan struct{}
	dialCount atomic.Int32
}

func (t *gatedDialTransport) Dial(ctx context.Context, addr string) (transport.Conn, error) {
	t.dialCount.Add(1)
	select {
	case <-t.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return t.inner.Dial(ctx, addr)
}

func (t *gatedDialTransport) Listen() (transport.Listener, error) { return t.inner.Listen() }
func (t *gatedDialTransport) Close() error                        { return t.inner.Close() }

// TestPool_Get_SingleFlightCoalescesDuringInFlightDial verifies that N
// concurrent Get() calls made WHILE a dial is in flight all coalesce onto the
// one dial runLoop is already performing: they block, then all return the
// same live connection once it completes — and only ONE Dial call is ever
// made, regardless of how many callers were waiting.
func TestPool_Get_SingleFlightCoalescesDuringInFlightDial(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hub := mem.NewHub()
	srvLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	srvT := hub.Transport("singleflight-agent:1", mem.WithCert(srvLeaf))
	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() { _ = tunnel.Serve(serveCtx, ln, nil) }()

	realCliT := hub.Transport("singleflight-client:1", mem.WithCert(srvLeaf))
	gated := &gatedDialTransport{inner: realCliT, gate: make(chan struct{})}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"singleflight-server": {Addr: "singleflight-agent:1"},
	}

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return gated, nil },
		zeroBackoffPolicy{},
		daemon.WallClock{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// newDialEntry sets dialing=true synchronously at construction — before
	// its run-loop goroutine is even scheduled — so every Get() launched from
	// this point on is guaranteed to observe an in-flight dial and take the
	// coalescing branch. There is no window where a Get() call could race
	// ahead of that invariant.
	const concurrency = 8
	conns := make([]daemon.Conn, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = pool.Get(ctx, "singleflight-server")
		}(i)
	}

	// Confirm the single in-flight Dial call has actually started before
	// releasing it — a bounded poll for a goroutine to start running, not a
	// sleep hoping a race resolves.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && gated.dialCount.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if gated.dialCount.Load() == 0 {
		t.Fatal("gated transport's Dial was never called within deadline")
	}

	close(gated.gate) // release the single blocked dial

	wg.Wait()

	if got := gated.dialCount.Load(); got != 1 {
		t.Errorf("Dial was called %d times; want exactly 1 — single-flight coalescing broken "+
			"(each concurrent Get() triggered its own dial instead of waiting on the in-flight one)", got)
	}

	var ref daemon.Conn
	for i := range concurrency {
		if errs[i] != nil {
			t.Errorf("Get[%d]: %v", i, errs[i])
			continue
		}
		if conns[i] == nil {
			t.Errorf("Get[%d]: nil conn with no error", i)
			continue
		}
		if ref == nil {
			ref = conns[i]
		} else if conns[i] != ref {
			t.Errorf("Get[%d] returned a different conn than Get[0] — single-flight broken", i)
		}
	}
}
