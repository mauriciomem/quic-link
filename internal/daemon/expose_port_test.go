package daemon_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// publishingRig is a connected session whose agent actually accepts publish
// requests, which the shared rigs in control_call_test.go deliberately do not:
// they exist to exercise the relay itself and their agents opt out of changes.
// A test about what a successful publish reports needs one that opts in.
func publishingRig(t *testing.T) (daemon.SessionPool, string) {
	t.Helper()
	hub := mem.NewHub()
	const agentAddr = "expose-port-agent:1"

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"srv": {Addr: agentAddr}}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	agentLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (agent): %v", err)
	}
	ln, err := hub.Transport(agentAddr, mem.WithCert(agentLeaf)).Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rtr, err := router.NewWithVhosts(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}
	// The operator's consent, which is what makes a publish succeed at all.
	go tunnel.Serve(ctx, ln, rtr, tunnel.ServeOpts{AllowRemoteRouteMutation: true}) //nolint:errcheck

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	cliT := hub.Transport("expose-port-client:1", mem.WithCert(clientLeaf))

	pool, err := daemon.NewRealPool(ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return cliT, nil },
		daemon.DefaultReconnectPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	t.Cleanup(pool.Close)
	waitForPoolState(t, pool, "srv", "connected", 10*time.Second)
	return pool, "srv"
}

// TestExposeJSON_ReportsThePortItIsHoldingNotAConstant asserts the property the
// reply shape exists for: the port a caller is told to use is the one this
// machine is actually answering names on, read from the listener it holds — not
// a number taken from configuration, and not one written into the code.
//
// It publishes twice, against two listeners on two different ports, and requires
// the answer to follow whichever listener the provider was given. One listener
// could not tell a real read apart from any constant that happened to match it;
// two can. The reply is produced by the code under test through a real connected
// session, so the assertion is about that code rather than about anything the
// test assembled.
func TestExposeJSON_ReportsThePortItIsHoldingNotAConstant(t *testing.T) {
	pool, server := publishingRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	type observation struct{ want, got int }
	var seen []observation

	for i, name := range []string{"first.srv.internal", "second.srv.internal"} {
		ln := heldHTTPListener(t)
		want := ln.Addr().(*net.TCPAddr).Port

		body, err := daemon.NewExposeProvider(pool, daemon.NamingListeners{HTTP: ln}).
			ExposeJSON(ctx, server, name, 3000+i)
		if err != nil {
			t.Fatalf("ExposeJSON(%s): %v", name, err)
		}
		var snap daemon.ExposeSnapshot
		if err := json.Unmarshal(body, &snap); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		seen = append(seen, observation{want: want, got: snap.HTTPPort})
	}

	if seen[0].want == seen[1].want {
		t.Fatal("the two listeners took the same port, so a constant would have passed; nothing was proven")
	}
	for _, o := range seen {
		if o.got != o.want {
			t.Errorf("reported port %d, want the port actually bound, %d — the port must come "+
				"from the listener this daemon holds, not from configuration", o.got, o.want)
		}
	}
}
