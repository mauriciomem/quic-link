/**
 * @spec-handoff
 * @interface test rig only: Serve's tests run on real loopback QUIC (transport.NewQUICListenTransport + identity.ListenTLSWithPairing(key, src, w.IsOpen))
 * @behavior
 *   - Serve receives the listener's own Conn (ALPNProvider, EKMProvider, RemoteAddrProvider all present) unless a test wraps it
 *   - the joiner computes its proof as Proof(secret, EKM(EKMLabel, ExporterContext(label), EKMLength)) on its own Conn
 * @see ./serve_test.go
 */

package pairing_test

// serve_rig_test.go holds the real-loopback-QUIC rig the Serve tests run on:
// a pairing-capable listener (identity.ListenTLSWithPairing on
// transport.NewQUICListenTransport, so every handshake goes through a Retry),
// a joiner that speaks the pairing frames, a Persister spy and a log capture.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/pairing"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// serveWait bounds every wait for a peer's answer or close.
const serveWait = 3 * time.Second

func genKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	k, err := identity.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	p, err := identity.PinForKey(k)
	if err != nil {
		t.Fatalf("PinForKey: %v", err)
	}
	return k, p
}

// serveRig is one pairing-capable listener backed by a test window.
type serveRig struct {
	h                     *winHarness
	srvKey, joinKey       ed25519.PrivateKey
	steadyKey             ed25519.PrivateKey
	srvPin, joinPin       string
	steadyPin             string
	ln                    transport.Listener
	addr                  string
	lnAddr                net.Addr
	acceptCtx             context.Context
	cancelAccept          context.CancelFunc
	serverConnsMu         sync.Mutex
	serverConns           []transport.Conn
	clientNetwork, client string // client socket: network and IP
}

// newServeRig listens on 127.0.0.1 (udp4) with a window of ttl.
func newServeRig(t *testing.T, ttl time.Duration) *serveRig {
	t.Helper()
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}
	return newServeRigOn(t, sock, ttl)
}

// newServeRigOn serves on sock, which it takes ownership of.
func newServeRigOn(t *testing.T, sock *net.UDPConn, ttl time.Duration) *serveRig {
	t.Helper()
	r := &serveRig{h: openTest(t, ttl), clientNetwork: "udp4", client: "127.0.0.1"}
	r.srvKey, r.srvPin = genKey(t)
	r.joinKey, r.joinPin = genKey(t)
	r.steadyKey, r.steadyPin = genKey(t)
	t.Cleanup(func() { sock.Close() })

	src := func() map[string]struct{} { return map[string]struct{}{r.steadyPin: {}} }
	conf, err := identity.ListenTLSWithPairing(r.srvKey, src, r.h.w.IsOpen)
	if err != nil {
		t.Fatalf("ListenTLSWithPairing: %v", err)
	}
	tr, err := transport.NewQUICListenTransport(sock, conf, nil)
	if err != nil {
		t.Fatalf("NewQUICListenTransport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	ln, err := tr.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	r.ln = ln
	r.lnAddr = ln.Addr()
	port := ln.Addr().(*net.UDPAddr).Port
	r.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	r.acceptCtx, r.cancelAccept = context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(func() {
		r.serverConnsMu.Lock()
		defer r.serverConnsMu.Unlock()
		for _, c := range r.serverConns {
			c.CloseWithError(0, "test done")
		}
	})
	t.Cleanup(r.cancelAccept)
	return r
}

// pairClient is both ends of one connection to the rig.
type pairClient struct {
	conn  transport.Conn // the dialling side
	srv   transport.Conn // the listener's side, as Accept returned it
	local netip.AddrPort // the dialling socket's address
}

// dial connects with key, offering protos, and accepts the listener's side.
func (r *serveRig) dial(t *testing.T, key ed25519.PrivateKey, protos ...string) *pairClient {
	t.Helper()
	c, err := r.tryDial(t, key, protos...)
	if err != nil {
		t.Fatalf("dial %s offering %q: %v", r.addr, protos, err)
	}
	return c
}

func (r *serveRig) clientTLS(t *testing.T, key ed25519.PrivateKey, protos ...string) *tls.Config {
	t.Helper()
	base, err := identity.ClientDialTLS(key, r.srvPin)
	if err != nil {
		t.Fatalf("ClientDialTLS: %v", err)
	}
	c := base.Clone()
	c.NextProtos = protos
	return c
}

// tryDial is dial that returns the dial error instead of failing the test.
func (r *serveRig) tryDial(t *testing.T, key ed25519.PrivateKey, protos ...string) (*pairClient, error) {
	t.Helper()
	sock, err := net.ListenUDP(r.clientNetwork, &net.UDPAddr{IP: net.ParseIP(r.client)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() })
	tr, err := transport.NewQUICTransport(sock, r.clientTLS(t, key, protos...), nil)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, r.addr)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { conn.CloseWithError(0, "test done") })
	srv, err := r.ln.Accept(ctx)
	if err != nil {
		t.Fatalf("listener accept: %v", err)
	}
	r.serverConnsMu.Lock()
	r.serverConns = append(r.serverConns, srv)
	r.serverConnsMu.Unlock()
	return &pairClient{conn: conn, srv: srv, local: sock.LocalAddr().(*net.UDPAddr).AddrPort()}, nil
}

// ekm is the client's exporter output for label.
func (c *pairClient) ekm(t *testing.T, label string) []byte {
	t.Helper()
	e, ok := c.conn.(transport.EKMProvider)
	if !ok {
		t.Fatalf("client Conn %T has no EKMProvider", c.conn)
	}
	out, err := e.ExportKeyingMaterial(pairing.EKMLabel, pairing.ExporterContext(label), pairing.EKMLength)
	if err != nil {
		t.Fatalf("client ExportKeyingMaterial: %v", err)
	}
	return out
}

// proofFor is a valid proof for label while the rig's window is open.
func (r *serveRig) proofFor(t *testing.T, c *pairClient, label string) []byte {
	t.Helper()
	s := secretOf(t, r.h.w)
	return pairing.Proof(s[:], c.ekm(t, label))
}

type deadliner interface{ SetReadDeadline(time.Time) error }

// openStream opens the request stream.
func (c *pairClient) openStream(t *testing.T) transport.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), serveWait)
	defer cancel()
	s, err := c.conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("client OpenStream: %v", err)
	}
	return s
}

// requestFrame is the framed request bytes.
func requestFrame(t *testing.T, req pairing.PairRequest) []byte {
	t.Helper()
	payload, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var b bytes.Buffer
	if err := pairing.WriteFrame(&b, payload); err != nil {
		t.Fatalf("frame request: %v", err)
	}
	return b.Bytes()
}

func writeAll(t *testing.T, s transport.Stream, b []byte) {
	t.Helper()
	if _, err := s.Write(b); err != nil {
		t.Fatalf("client write: %v", err)
	}
}

// readResponse reads one response frame within d.
func readResponse(s transport.Stream, d time.Duration) (pairing.PairResponse, error) {
	if dl, ok := s.(deadliner); ok {
		_ = dl.SetReadDeadline(time.Now().Add(d))
	}
	payload, err := pairing.ReadFrame(s)
	if err != nil {
		return pairing.PairResponse{}, err
	}
	return pairing.ParsePairResponse(payload)
}

// trySend sends raw on a new stream, ignoring every error.
func (c *pairClient) trySend(raw []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), serveWait)
	defer cancel()
	if s, err := c.conn.OpenStream(ctx); err == nil {
		_, _ = s.Write(raw)
	}
}

// exchange sends raw request bytes on a new stream and reads the answer.
func (c *pairClient) exchange(t *testing.T, raw []byte) (pairing.PairResponse, error) {
	t.Helper()
	s := c.openStream(t)
	writeAll(t, s, raw)
	return readResponse(s, serveWait)
}

// wantStatus requires an answer with status want and an empty msg.
func wantStatus(t *testing.T, what string, resp pairing.PairResponse, err error, want pairing.Status) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: no answer: %v (want status %v)", what, err, want)
	}
	if resp.Status != want {
		t.Errorf("%s: status %v, want %v", what, resp.Status, want)
	}
	if want != pairing.StatusUnsupportedMethod && resp.Msg != "" {
		t.Errorf("%s: msg %q, want empty", what, resp.Msg)
	}
}

// waitClosed waits for the dialling side to see the connection closed and
// returns the application close code the listener used.
func (c *pairClient) waitClosed(d time.Duration) (code uint64, closed, isApp bool) {
	select {
	case <-c.conn.Context().Done():
	case <-time.After(d):
		return 0, false, false
	}
	var ae *quic.ApplicationError
	if errors.As(context.Cause(c.conn.Context()), &ae) && ae.Remote {
		return uint64(ae.ErrorCode), true, true
	}
	return 0, true, false
}

// wantClosedWith requires the listener to close the connection with code.
func (c *pairClient) wantClosedWith(t *testing.T, what string, want uint64, d time.Duration) {
	t.Helper()
	code, closed, isApp := c.waitClosed(d)
	switch {
	case !closed:
		t.Errorf("%s: connection not closed within %v; want close code %#x", what, d, want)
	case !isApp:
		t.Errorf("%s: connection ended with %v, want a remote application close %#x", what, context.Cause(c.conn.Context()), want)
	case code != want:
		t.Errorf("%s: closed with %#x, want %#x", what, code, want)
	}
}

// serveRun is one Serve call in the background.
type serveRun struct {
	done   chan error
	start  time.Time
	cancel context.CancelFunc // ends Serve's ctx (shutdown)
}

// runServe runs serve in the background; at cleanup it requires it to have
// returned (after closing the server conn, which must end any Serve).
func runServe(t *testing.T, srv transport.Conn, serve func(ctx context.Context) error) *serveRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &serveRun{done: make(chan error, 1), start: time.Now(), cancel: cancel}
	go func() { r.done <- serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		srv.CloseWithError(0, "test done")
		select {
		case <-r.done:
		case <-time.After(serveWait):
			t.Error("Serve did not return after its ctx was cancelled and its conn closed")
		}
	})
	return r
}

// wait returns Serve's result, or false if it is still running after d.
func (r *serveRun) wait(d time.Duration) (error, time.Duration, bool) {
	select {
	case err := <-r.done:
		r.done <- err // keep it for the cleanup
		return err, time.Since(r.start), true
	case <-time.After(d):
		return nil, 0, false
	}
}

// verifyNoLeakWhileLive requires that no goroutine started after opt was
// taken is still running, while Serve's ctx is still live: a goroutine that
// waits only for the caller's ctx is a per-exchange leak for the listener's
// lifetime. The connections' own run loops may still be winding down.
func (r *serveRun) verifyNoLeakWhileLive(t *testing.T, opt goleak.Option) {
	t.Helper()
	goleak.VerifyNone(t, opt, goleak.IgnoreAnyFunction("github.com/quic-go/quic-go.(*Conn).run"))
}

type persistCall struct {
	pin, label string
	from       netip.AddrPort
}

// persistSpy is a Persister. Persist and Confirm can be gated; entering
// either is signalled.
type persistSpy struct {
	mu             sync.Mutex
	calls          []persistCall
	confirms       []string
	persistErr     error
	confirmErr     error
	persistGate    chan struct{}
	confirmGate    chan struct{}
	persistEntered chan struct{}
	confirmEntered chan struct{}
}

func newPersistSpy() *persistSpy {
	return &persistSpy{persistEntered: make(chan struct{}, 8), confirmEntered: make(chan struct{}, 8)}
}

func (p *persistSpy) Persist(pin, label string, from netip.AddrPort) error {
	p.mu.Lock()
	p.calls = append(p.calls, persistCall{pin, label, from})
	p.mu.Unlock()
	p.persistEntered <- struct{}{}
	if p.persistGate != nil {
		<-p.persistGate
	}
	return p.persistErr
}

func (p *persistSpy) persisted() []persistCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]persistCall(nil), p.calls...)
}

func (p *persistSpy) confirmed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.confirms...)
}

// confirmSpy is a persistSpy that also implements Confirmer.
type confirmSpy struct{ *persistSpy }

func (p confirmSpy) Confirm(pin string) error {
	p.mu.Lock()
	p.confirms = append(p.confirms, pin)
	p.mu.Unlock()
	p.confirmEntered <- struct{}{}
	if p.confirmGate != nil {
		<-p.confirmGate
	}
	return p.confirmErr
}

var (
	_ pairing.Persister = (*persistSpy)(nil)
	_ pairing.Confirmer = confirmSpy{}
)

// logCapture is a JSON slog sink safe for concurrent use.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newLogCapture() (*logCapture, *slog.Logger) {
	l := &logCapture{}
	return l, slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// records returns the log lines at level.
func (l *logCapture) records(level slog.Level) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(l.String()), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Level string `json:"level"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Level == level.String() {
			out = append(out, line)
		}
	}
	return out
}

// wantNoSecrets requires the log to hold none of the given secrets in any
// common encoding, and not the full joiner pin.
func (l *logCapture) wantNoSecrets(t *testing.T, fullPin string, secrets map[string][]byte) {
	t.Helper()
	logs := l.String()
	if fullPin != "" && strings.Contains(logs, fullPin) {
		t.Errorf("log carries the full joiner pin; only its 8-character prefix may appear:\n%s", logs)
	}
	for name, s := range secrets {
		if len(s) == 0 {
			continue
		}
		for enc, v := range map[string]string{
			"hex":       hex.EncodeToString(s),
			"base64":    base64.StdEncoding.EncodeToString(s),
			"base64url": base64.RawURLEncoding.EncodeToString(s),
		} {
			if strings.Contains(logs, v) {
				t.Errorf("log carries the %s (%s):\n%s", name, enc, logs)
			}
		}
	}
}
