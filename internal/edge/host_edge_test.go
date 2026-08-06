package edge_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/edge"
	"github.com/mauriciomem/quic-link/internal/names"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// countingSource wraps a ConnSource and records how many times a session was
// asked for. A refusal that never asks is the proof that nothing was opened.
type countingSource struct {
	inner edge.ConnSource
	asked atomic.Int64
}

func (c *countingSource) OpenConn(ctx context.Context, server string) (tunnel.StreamConn, string, error) {
	c.asked.Add(1)
	return c.inner.OpenConn(ctx, server)
}

// hostEdgeRig stands up an agent that publishes one hostname, a client session
// to it, and the name-routed edge in front. The origin records exactly the
// bytes it received.
type hostEdgeRig struct {
	addr     string
	received chan []byte
	src      *countingSource
}

func newHostEdgeRig(t *testing.T) *hostEdgeRig {
	t.Helper()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	agentLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hub := mem.NewHub()
	const agentAddr = "vhost-agent:1"
	srvT := hub.Transport(agentAddr, mem.WithCert(agentLeaf))
	cliT := hub.Transport("vhost-client:1", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatal(err)
	}

	// The origin: records the bytes it is handed, verbatim.
	received := make(chan []byte, 8)
	originLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { originLn.Close() })
	go func() {
		for {
			c, err := originLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if n > 0 {
					received <- append([]byte(nil), buf[:n]...)
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
			}(c)
		}
	}()

	rtr, err := router.NewWithVhosts(nil, map[string]string{
		"grafana.server1.internal": "tcp://" + originLn.Addr().String(),
		"*.server1.internal":       "tcp://" + originLn.Addr().String(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	actx, acancel := context.WithCancel(context.Background())
	t.Cleanup(func() { acancel(); ln.Close() })
	go tunnel.Serve(actx, ln, rtr) //nolint:errcheck

	conn, err := cliT.Dial(context.Background(), agentAddr)
	if err != nil {
		t.Fatal(err)
	}
	src := &countingSource{inner: fixedSource{conn: conn}}

	edgeLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ectx, ecancel := context.WithCancel(context.Background())
	e := edge.NewHostEdge(ectx, edgeLn, names.NewZone("internal", []string{"server1"}), src, edge.HTTPPeeker{})
	t.Cleanup(func() { ecancel(); e.Close() })

	return &hostEdgeRig{addr: edgeLn.Addr().String(), received: received, src: src}
}

type fixedSource struct{ conn transport.Conn }

func (f fixedSource) OpenConn(context.Context, string) (tunnel.StreamConn, string, error) {
	return f.conn, "testpin1", nil
}

// send writes raw bytes to the edge and returns whatever comes back.
func (r *hostEdgeRig) send(t *testing.T, raw string) (string, error) {
	t.Helper()
	c, err := net.Dial("tcp4", r.addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		return "", err
	}
	out, err := io.ReadAll(c)
	return string(out), err
}

// TestHostEdge_RoutesByName is the happy path, and it also proves the bytes
// arrive exactly as sent.
func TestHostEdge_RoutesByName(t *testing.T) {
	rig := newHostEdgeRig(t)
	// Deliberately awkward: an unusual header case, no space after the colon,
	// extra padding, and a body. Anything that rewrote the request on the way
	// through would change at least one of these, while a request written in
	// canonical form would survive being rewritten and prove nothing.
	raw := "POST /x HTTP/1.1\r\nHost:grafana.server1.internal\r\nX-Odd-CASE:  Kept  \r\nContent-Length: 5\r\n\r\nhello"
	resp, err := rig.send(t, raw)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("response = %q", resp)
	}
	select {
	case got := <-rig.received:
		if string(got) != raw {
			t.Errorf("the service received bytes that are not what was sent:\n got %q\nwant %q", got, raw)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the service received nothing")
	}
}

// TestHostEdge_AnUnservedNameOpensNothing is the single most important test in
// this step. A page anywhere on the internet can make a browser connect here
// and send whatever name it likes; if that name is not one we serve, nothing
// must happen at all — not a refusal from the far end, nothing opened.
//
// If this test is ever deleted, the check it covers can be removed with the
// rest of the suite still green.
func TestHostEdge_AnUnservedNameOpensNothing(t *testing.T) {
	rig := newHostEdgeRig(t)

	for _, host := range []string{
		"evil.example",
		"grafana.server1.internal.evil.example",
		"notinternal",
		"internal.evil.example",
		"127.0.0.1",
		"127.0.0.1:18080",
		"[::1]",
	} {
		t.Run(host, func(t *testing.T) {
			before := rig.src.asked.Load()
			resp, _ := rig.send(t, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
			if resp != "" {
				t.Errorf("a name we do not serve got a reply: %q", resp)
			}
			if after := rig.src.asked.Load(); after != before {
				t.Errorf("a session was asked for on behalf of %q; nothing must be opened", host)
			}
			select {
			case got := <-rig.received:
				t.Errorf("bytes reached a service on behalf of %q: %q", host, got)
			default:
			}
		})
	}
}

// TestHostEdge_AmbiguousRequestsOpenNothing: two names in one request are two
// answers to where it is going, and either could be the one the far end acts on.
func TestHostEdge_AmbiguousRequestsOpenNothing(t *testing.T) {
	rig := newHostEdgeRig(t)
	for name, raw := range map[string]string{
		"two hosts":       "GET / HTTP/1.1\r\nHost: grafana.server1.internal\r\nHost: evil.example\r\n\r\n",
		"line disagrees":  "GET http://evil.example/ HTTP/1.1\r\nHost: grafana.server1.internal\r\n\r\n",
		"no host":         "GET / HTTP/1.0\r\n\r\n",
		"folded":          "GET / HTTP/1.1\r\nHost: grafana.server1.internal\r\nX-A: 1\r\n\tX-B: 2\r\n\r\n",
		"version 2 hello": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			before := rig.src.asked.Load()
			if resp, _ := rig.send(t, raw); resp != "" {
				t.Errorf("got a reply: %q", resp)
			}
			if after := rig.src.asked.Load(); after != before {
				t.Error("a session was asked for; nothing must be opened")
			}
		})
	}
}

// TestHostEdge_WildcardNamesReachTheService covers the pattern entry.
func TestHostEdge_WildcardNamesReachTheService(t *testing.T) {
	rig := newHostEdgeRig(t)
	resp, err := rig.send(t, "GET / HTTP/1.1\r\nHost: anything.server1.internal\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response = %q", resp)
	}
	<-rig.received
}

// TestHostEdge_RealClientWorks uses net/http as the client, which is the shape
// a browser actually sends and which no hand-written fixture fully imitates.
func TestHostEdge_RealClientWorks(t *testing.T) {
	rig := newHostEdgeRig(t)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", rig.addr)
	}}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get("http://grafana.server1.internal/dashboards")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	got := <-rig.received
	// A real client sends the port in the Host header when it is not the
	// default; the edge must have stripped it before checking the name and
	// still passed the original bytes through.
	br := bufio.NewReader(strings.NewReader(string(got)))
	req, err := http.ReadRequest(br)
	if err != nil {
		t.Fatalf("the service received something unparseable: %v", err)
	}
	if req.Host == "" || !strings.HasPrefix(req.Host, "grafana.server1.internal") {
		t.Errorf("the service saw Host %q", req.Host)
	}
}
