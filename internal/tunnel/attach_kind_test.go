package tunnel

// attach_kind_test.go pins the stream header DoAttach actually puts on the
// wire. DoAttach is the single client-side helper every local listener uses to
// turn an accepted connection into a stream, and it always stamps the same
// kind. That is correct for what it serves today — listeners that know their
// target up front — but it means a listener which must name a *host* instead of
// a target cannot use it, and would silently send the wrong kind if it tried.
//
// These tests exist so that adding a second attach path is visibly additive:
// if the assertions below still hold afterwards, nothing that already worked
// changed shape.

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// recordingPolicy captures every header the agent's router authorized. The
// authorization call-site receives the header verbatim, so this observes the
// real bytes the client sent rather than a re-derivation of them.
type recordingPolicy struct {
	mu   sync.Mutex
	seen []proto.Header
}

func (p *recordingPolicy) Authorize(_ router.Identity, h proto.Header) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, h)
	return nil
}

func (p *recordingPolicy) headers() []proto.Header {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]proto.Header, len(p.seen))
	copy(out, p.seen)
	return out
}

// newRecordingSetup wires a mem-transport agent whose router authorizes through
// pol. It is deliberately separate from newMemSetup: that helper builds its
// router with a nil policy, and threading an option through it would change a
// harness several unrelated tests depend on.
func newRecordingSetup(t *testing.T, pol router.Policy) (transport.Transport, string) {
	t.Helper()

	clientLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (client): %v", err)
	}
	serverLeaf, _, err := mem.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (agent): %v", err)
	}

	hub := mem.NewHub()
	const agentAddr = "agent-kind:1"
	srvT := hub.Transport(agentAddr, mem.WithCert(serverLeaf))
	cliT := hub.Transport("client-kind:1", mem.WithCert(clientLeaf))

	ln, err := srvT.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	echoLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go runEchoSrv(echoLn)

	rtr, err := router.New(map[string]string{"ssh": "tcp://" + echoLn.Addr().String()}, pol)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		ln.Close()
	})
	go Serve(ctx, ln, rtr) //nolint:errcheck

	return cliT, agentAddr
}

// TestDoAttach_StampsTCPKindAndNoHost pins the header DoAttach emits: the tcp
// kind, the caller's target, and — the part that matters for anything hostname
// routed — an empty host field. An agent resolving by host would find nothing
// to resolve.
func TestDoAttach_StampsTCPKindAndNoHost(t *testing.T) {
	t.Parallel()
	pol := &recordingPolicy{}
	cliT, agentAddr := newRecordingSetup(t, pol)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := cliT.Dial(ctx, agentAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	localA, localB := net.Pipe()
	defer localA.Close()

	reqid := NewReqID()
	done := make(chan error, 1)
	go func() { done <- DoAttach(ctx, conn, localA, "ssh", reqid, nil) }()

	// Drive one byte through so the agent has certainly processed the header.
	if _, err := localB.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 1)
	localB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(localB, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	localB.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DoAttach did not return after local close")
	}

	hdrs := pol.headers()
	if len(hdrs) != 1 {
		t.Fatalf("want exactly one authorized header, got %d: %+v", len(hdrs), hdrs)
	}
	h := hdrs[0]

	if h.Kind != proto.KindTCP {
		t.Errorf("kind: got %q, want %q", h.Kind, proto.KindTCP)
	}
	if h.Target != "ssh" {
		t.Errorf("target: got %q, want %q", h.Target, "ssh")
	}
	if h.Host != "" {
		t.Errorf("host: got %q, want empty — DoAttach never sets a host", h.Host)
	}
	if h.Meta["reqid"] != reqid {
		t.Errorf("reqid: got %q, want %q", h.Meta["reqid"], reqid)
	}
}

// TestHTTPKindIsSpecifiedButUnserved pins the other half of the picture: the
// wire format already defines a hostname-routed kind and already requires a
// host on it, but no agent resolves one. A client sending it today is answered
// "unknown target", which is the documented placeholder rather than a defect.
//
// The first assertion is what makes a later change cheap to review: if the
// parser ever stops requiring a host, hostname routing loses its only
// guaranteed input.
func TestHTTPKindIsSpecifiedButUnserved(t *testing.T) {
	t.Parallel()

	// Round-trip through the real encoder, so this exercises the same bytes a
	// peer would send rather than the in-memory struct.
	mustMarshal := func(h proto.Header) []byte {
		t.Helper()
		b, err := h.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return b
	}

	if _, err := proto.ParseHeader(mustMarshal(proto.Header{Kind: proto.KindHTTP})); err == nil {
		t.Error("a hostname-routed header with no host must be rejected by the parser")
	}
	if _, err := proto.ParseHeader(mustMarshal(proto.Header{Kind: proto.KindHTTP, Host: "grafana.server1.internal"})); err != nil {
		t.Errorf("a hostname-routed header with a host must parse: %v", err)
	}

	// The agent side: a router has no hostname table at all, so a header
	// carrying only a host resolves nothing.
	rtr, err := router.New(nil, nil)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	_, err = rtr.Dial(context.Background(), router.Identity{}, proto.Header{
		Kind: proto.KindHTTP,
		Host: "grafana.server1.internal",
	})
	if err == nil {
		t.Fatal("want an error: nothing resolves a hostname today")
	}
	if !errors.Is(err, router.ErrUnknownTarget) {
		t.Errorf("want the unknown-target error, got: %v", err)
	}
}
