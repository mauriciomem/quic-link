/**
 * @spec-handoff
 * @interface Serve(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger) error; Persister{Persist(pin, label string, from netip.AddrPort) error}; optional Confirmer{Confirm(pin string) error}; seam serveWith(..., serveOpts{deadline}) with defaultServeOpts().deadline == proto.ResponseDeadline (10 s)
 * @behavior
 *   - preconditions, else CloseWithError(CodePairRejected) + non-nil error with NO Attempt and NO Persist: ALPNProvider == transport.ALPNPair, EKMProvider, RemoteAddrProvider giving a *net.UDPAddr with a valid AddrPort, a peer certificate (pin = identity.PinFromCert(leaf)), non-nil w, p, log
 *   - AcceptStream within the deadline (else close CodePairRejected); further streams reset with proto.StreamResetCode while Serve runs; ReadFrame under a read deadline (a stalled frame ends in a close)
 *   - frame error -> bad_header; ParsePairRequest error -> StatusForParseError (unsupported_method's msg names token-hmac-v1; every other msg ""); none of these call Attempt
 *   - EKM(EKMLabel, ExporterContext(req.Label), EKMLength); st := w.Attempt(from.Addr(), proof, ekm) - a request arriving after close is still read and proof-checked and answered window_closed
 *   - ok -> Persist(pin, label, from) BEFORE any response byte; Persist error -> answer window_closed, window stays closed, ERROR log naming the error (file); else ok
 *   - after the ok response is written: Confirm(pin) if p implements Confirmer; its error is WARN only
 *   - then wait for the peer to close or the deadline, and CloseWithError(0, "")
 *   - logs carry at most the pin's 8-char prefix: never the full pin, blob, secret, proof or EKM
 * @edge-cases
 *   - dual-stack listener ([::]): an IPv4 client is budgeted as its IPv4 /32
 * @see ./serve.go ./window.go ./serve_rig_test.go
 */

package pairing_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/mauriciomem/quic-link/internal/pairing"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

const testLabel = "laptop"

// serveDefault runs Serve with the production deadline.
func serveDefault(srv transport.Conn, w *pairing.Window, p pairing.Persister, log *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error { return pairing.Serve(ctx, srv, w, p, log) }
}

func serveWithin(srv transport.Conn, w *pairing.Window, p pairing.Persister, log *slog.Logger, d time.Duration) func(context.Context) error {
	return func(ctx context.Context) error { return pairing.ServeWithDeadline(ctx, srv, w, p, log, d) }
}

func TestServe_PersistsBeforeOK(t *testing.T) {
	t.Run("Persist completes before any response byte, Confirm after the response", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		spy := newPersistSpy()
		spy.persistGate = make(chan struct{})
		spy.confirmGate = make(chan struct{})
		releasePersist, releaseConfirm := closer(t, spy.persistGate), closer(t, spy.confirmGate)
		logs, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		run := runServe(t, c.srv, serveDefault(c.srv, r.h.w, confirmSpy{spy}, log))
		blob := r.h.w.Blob()
		secret := secretOf(t, r.h.w)
		ekm := c.ekm(t, testLabel)
		proof := r.proofFor(t, c, testLabel)

		s := c.openStream(t)
		writeAll(t, s, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: proof}))
		select {
		case <-spy.persistEntered:
		case <-time.After(serveWait):
			t.Fatal("Persist was not called for a valid proof")
		}
		if resp, err := readResponse(s, 300*time.Millisecond); err == nil {
			t.Fatalf("got response %+v while Persist was still running; the ok must follow a completed Persist", resp)
		}
		releasePersist()
		resp, err := readResponse(s, serveWait)
		wantStatus(t, "valid proof", resp, err, pairing.StatusOK)
		select {
		case <-spy.confirmEntered:
		case <-time.After(serveWait):
			t.Fatal("Confirm was not called after the ok response")
		}
		releaseConfirm()

		calls := spy.persisted()
		if len(calls) != 1 {
			t.Fatalf("Persist called %d times, want 1", len(calls))
		}
		want := persistCall{pin: r.joinPin, label: testLabel, from: c.local}
		if calls[0] != want {
			t.Errorf("Persist(%q, %q, %v), want Persist(%q, %q, %v) (joiner pin, request label, joiner UDP source)",
				calls[0].pin, calls[0].label, calls[0].from, want.pin, want.label, want.from)
		}
		if got := spy.confirmed(); len(got) != 1 || got[0] != r.joinPin {
			t.Errorf("Confirm calls %q, want exactly [%q]", got, r.joinPin)
		}
		if r.h.w.IsOpen() {
			t.Error("window still open after a successful pairing")
		}
		if res, ok := waitResult(t, r.h.w); !ok || res.Reason != pairing.ReasonPaired {
			t.Errorf("window result %+v (ended %v), want ReasonPaired", res, ok)
		}
		if n := r.h.vlog.count(); n != 1 {
			t.Errorf("proof verified %d times, want 1", n)
		}

		c.conn.CloseWithError(0, "joiner done")
		if _, _, ok := run.wait(serveWait); !ok {
			t.Error("Serve still running after the joiner closed the connection")
		}
		logs.wantNoSecrets(t, r.joinPin, map[string][]byte{"secret": secret[:], "proof": proof, "EKM": ekm, "blob": []byte(blob)})
		if strings.Contains(logs.String(), blob) {
			t.Error("log carries the join blob")
		}
	})

	t.Run("a Persister without Confirmer gets ok", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		spy := newPersistSpy()
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		runServe(t, c.srv, serveDefault(c.srv, r.h.w, spy, log))
		resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: r.proofFor(t, c, testLabel)}))
		wantStatus(t, "valid proof", resp, err, pairing.StatusOK)
		if n := len(spy.persisted()); n != 1 {
			t.Errorf("Persist called %d times, want 1", n)
		}
	})

	t.Run("a Confirm failure is a WARN and the answer stays ok", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		spy := newPersistSpy()
		spy.confirmErr = errors.New("promote: lock timeout")
		logs, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		run := runServe(t, c.srv, serveDefault(c.srv, r.h.w, confirmSpy{spy}, log))
		resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: r.proofFor(t, c, testLabel)}))
		wantStatus(t, "valid proof", resp, err, pairing.StatusOK)
		select {
		case <-spy.confirmEntered:
		case <-time.After(serveWait):
			t.Fatal("Confirm was not called")
		}
		c.conn.CloseWithError(0, "joiner done")
		run.wait(serveWait)
		if len(logs.records(slog.LevelWarn)) == 0 {
			t.Errorf("no WARN record for the Confirm failure:\n%s", logs)
		}
		if e := logs.records(slog.LevelError); len(e) != 0 {
			t.Errorf("a Confirm failure logged at ERROR (the pin is authorized either way): %q", e)
		}
	})
}

// closer returns an idempotent close of ch, also registered as a cleanup.
func closer(t *testing.T, ch chan struct{}) func() {
	done := false
	f := func() {
		if !done {
			done = true
			close(ch)
		}
	}
	t.Cleanup(f)
	return f
}

func TestServe_PersistFailureIsNotOKAndWindowStaysClosed(t *testing.T) {
	routeLeakCheck(t)
	r := newServeRig(t, time.Minute)
	stateFile := filepath.Join(t.TempDir(), "authorized_clients")
	spy := newPersistSpy()
	spy.persistErr = fmt.Errorf("append %s: lock timeout", stateFile)
	logs, log := newLogCapture()
	c := r.dial(t, r.joinKey, transport.ALPNPair)
	run := runServe(t, c.srv, serveDefault(c.srv, r.h.w, confirmSpy{spy}, log))
	secret := secretOf(t, r.h.w)
	proof := r.proofFor(t, c, testLabel)

	resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: proof}))
	wantStatus(t, "valid proof, Persist failing", resp, err, pairing.StatusWindowClosed)
	if n := len(spy.persisted()); n != 1 {
		t.Errorf("Persist called %d times, want 1", n)
	}
	if got := spy.confirmed(); len(got) != 0 {
		t.Errorf("Confirm called %q after a failed Persist; nothing may be confirmed", got)
	}
	c.conn.CloseWithError(0, "joiner done")
	if _, _, ok := run.wait(serveWait); !ok {
		t.Error("Serve still running after the joiner closed the connection")
	}

	if r.h.w.IsOpen() {
		t.Error("window reopened after a failed Persist; it must stay closed")
	}
	if res, ok := waitResult(t, r.h.w); !ok || res.Reason != pairing.ReasonPaired {
		t.Errorf("window result %+v (ended %v), want ReasonPaired (no rollback)", res, ok)
	}
	errs := logs.records(slog.LevelError)
	found := false
	for _, e := range errs {
		if strings.Contains(e, stateFile) {
			found = true
		}
	}
	if !found {
		t.Errorf("no ERROR record naming %s; got ERROR records %q", stateFile, errs)
	}
	logs.wantNoSecrets(t, r.joinPin, map[string][]byte{"secret": secret[:], "proof": proof})

	t.Run("a new pairing handshake is refused at ALPN", func(t *testing.T) {
		_, err := r.tryDial(t, r.joinKey, transport.ALPNPair)
		var te *quic.TransportError
		if !errors.As(err, &te) || te.ErrorCode != 0x178 {
			t.Errorf("pair1 dial after a failed Persist = %v, want TLS alert 0x178 (window closed)", err)
		}
	})
}

func TestServe_LabelTamperIsBadProof(t *testing.T) {
	routeLeakCheck(t)
	r := newServeRig(t, time.Minute)
	spy := newPersistSpy()
	_, log := newLogCapture()
	c := r.dial(t, r.joinKey, transport.ALPNPair)
	runServe(t, c.srv, serveDefault(c.srv, r.h.w, spy, log))

	// The proof binds label A through the exporter context; the request
	// carries label B.
	proof := r.proofFor(t, c, "label-A")
	resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: "label-B", Proof: proof}))
	wantStatus(t, "proof over another label", resp, err, pairing.StatusBadProof)
	if n := r.h.vlog.count(); n != 1 {
		t.Errorf("proof verified %d times, want 1", n)
	}
	if _, _, ekm, got := lastVerify(t, r); string(got) != string(proof) || string(ekm) != string(c.ekm(t, "label-B")) {
		t.Error("Attempt was not given the request's proof and the EKM bound to the request's label")
	}
	if n := len(spy.persisted()); n != 0 {
		t.Errorf("Persist called %d times for a bad proof", n)
	}
	if !r.h.w.IsOpen() {
		t.Error("window closed by a bad proof")
	}
	if st := r.h.w.Status(); st.SourcesTracked != 1 {
		t.Errorf("SourcesTracked = %d after one bad proof, want 1", st.SourcesTracked)
	}
}

// lastVerify returns the most recent verify call's inputs.
func lastVerify(t *testing.T, r *serveRig) (key [pairing.SecretLen]byte, n int, ekm, got []byte) {
	t.Helper()
	if r.h.vlog.count() == 0 {
		t.Fatal("verify was never called")
	}
	return r.h.vlog.last(t)
}

func TestServe_WindowClosedAfterHandshakeAnswersWindowClosed(t *testing.T) {
	const ttl = time.Minute
	for _, tc := range []struct {
		name    string
		advance time.Duration
		want    pairing.Status
	}{
		{"request just before the deadline is served", ttl - time.Millisecond, pairing.StatusOK},
		{"request at the deadline answers window_closed", ttl, pairing.StatusWindowClosed},
		{"request after the deadline answers window_closed", 2 * ttl, pairing.StatusWindowClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routeLeakCheck(t)
			r := newServeRig(t, ttl)
			spy := newPersistSpy()
			_, log := newLogCapture()
			c := r.dial(t, r.joinKey, transport.ALPNPair) // handshake while open
			runServe(t, c.srv, serveDefault(c.srv, r.h.w, spy, log))
			proof := r.proofFor(t, c, testLabel) // a valid proof, computed while open

			r.h.clock.Advance(tc.advance)
			resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: proof}))
			wantStatus(t, "request", resp, err, tc.want)
			if n := r.h.vlog.count(); n != 1 {
				t.Fatalf("proof verified %d times, want exactly 1 on every path", n)
			}
			key, _, ekm, got := lastVerify(t, r)
			if string(got) != string(proof) || string(ekm) != string(c.ekm(t, testLabel)) {
				t.Error("verify did not get the request's proof and EKM")
			}
			persisted := spy.persisted()
			if tc.want == pairing.StatusOK {
				if len(persisted) != 1 {
					t.Errorf("Persist called %d times before the deadline, want 1", len(persisted))
				}
				return
			}
			if key != patternKey(standInSeed) {
				t.Errorf("after the deadline the proof was checked with %x, want the stand-in key %x", key, patternKey(standInSeed))
			}
			if len(persisted) != 0 {
				t.Errorf("Persist called %d times for a request after the deadline; nothing may be saved", len(persisted))
			}
			if res, ok := waitResult(t, r.h.w); !ok || res.Reason != pairing.ReasonExpired {
				t.Errorf("window result %+v (ended %v), want ReasonExpired", res, ok)
			}
		})
	}
}

// Conn wrappers that drop optional interfaces of a real connection. An
// embedded interface carries only the methods it declares.
type (
	bareConn struct{ transport.Conn }
	// alpnRemote: ALPN and remote address, no EKM.
	alpnRemote struct{ transport.Conn }
	// alpnEKM: ALPN and EKM, no remote address.
	alpnEKM struct{ transport.Conn }
	// alpnEKMAddr: ALPN, EKM and the given remote address.
	alpnEKMAddr struct {
		transport.Conn
		addr net.Addr
	}
	// noCert: every interface, but no peer certificate.
	noCert struct{ transport.Conn }
)

func np(c transport.Conn) string { return c.(transport.ALPNProvider).NegotiatedProtocol() }
func ekmOf(c transport.Conn, l string, ctx []byte, n int) ([]byte, error) {
	return c.(transport.EKMProvider).ExportKeyingMaterial(l, ctx, n)
}
func remoteOf(c transport.Conn) net.Addr { return c.(transport.RemoteAddrProvider).RemoteAddr() }

func (c alpnRemote) NegotiatedProtocol() string { return np(c.Conn) }
func (c alpnRemote) RemoteAddr() net.Addr       { return remoteOf(c.Conn) }
func (c alpnEKM) NegotiatedProtocol() string    { return np(c.Conn) }
func (c alpnEKM) ExportKeyingMaterial(l string, x []byte, n int) ([]byte, error) {
	return ekmOf(c.Conn, l, x, n)
}
func (c alpnEKMAddr) NegotiatedProtocol() string { return np(c.Conn) }
func (c alpnEKMAddr) ExportKeyingMaterial(l string, x []byte, n int) ([]byte, error) {
	return ekmOf(c.Conn, l, x, n)
}
func (c alpnEKMAddr) RemoteAddr() net.Addr  { return c.addr }
func (c noCert) NegotiatedProtocol() string { return np(c.Conn) }
func (c noCert) ExportKeyingMaterial(l string, x []byte, n int) ([]byte, error) {
	return ekmOf(c.Conn, l, x, n)
}
func (c noCert) RemoteAddr() net.Addr                  { return remoteOf(c.Conn) }
func (c noCert) PeerCertificates() []*x509.Certificate { return nil }

func TestServe_RefusesWithoutAttempt(t *testing.T) {
	type args struct {
		conn transport.Conn
		w    *pairing.Window
		p    pairing.Persister
		log  *slog.Logger
	}
	for _, tc := range []struct {
		name   string
		steady bool // dial the steady branch instead of pairing
		mod    func(a *args)
	}{
		{"connection negotiated quic-link/1", true, nil},
		{"no ALPNProvider", false, func(a *args) { a.conn = bareConn{a.conn} }},
		{"no EKMProvider", false, func(a *args) { a.conn = alpnRemote{a.conn} }},
		{"no RemoteAddrProvider", false, func(a *args) { a.conn = alpnEKM{a.conn} }},
		{"remote address is not UDP", false, func(a *args) {
			a.conn = alpnEKMAddr{a.conn, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}}
		}},
		{"remote UDP address is invalid", false, func(a *args) { a.conn = alpnEKMAddr{a.conn, &net.UDPAddr{}} }},
		{"remote address is nil", false, func(a *args) { a.conn = alpnEKMAddr{a.conn, nil} }},
		{"no peer certificate", false, func(a *args) { a.conn = noCert{a.conn} }},
		{"nil window", false, func(a *args) { a.w = nil }},
		{"nil persister", false, func(a *args) { a.p = nil }},
		{"nil logger", false, func(a *args) { a.log = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routeLeakCheck(t)
			r := newServeRig(t, time.Minute)
			spy := newPersistSpy()
			_, log := newLogCapture()
			var c *pairClient
			if tc.steady {
				c = r.dial(t, r.steadyKey, transport.ALPN)
			} else {
				c = r.dial(t, r.joinKey, transport.ALPNPair)
			}
			a := args{conn: c.srv, w: r.h.w, p: spy, log: log}
			if tc.mod != nil {
				tc.mod(&a)
			}
			// A valid request goes on the wire, so only the refusal keeps it
			// from reaching Attempt. Write errors are ignored: a refusal may
			// close the connection before the request is sent.
			raw := requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: r.proofFor(t, c, testLabel)})
			run := runServe(t, c.srv, func(ctx context.Context) error { return pairing.Serve(ctx, a.conn, a.w, a.p, a.log) })
			c.trySend(raw)

			c.wantClosedWith(t, "refused connection", pairing.CodePairRejected, serveWait)
			err, _, ok := run.wait(serveWait)
			switch {
			case !ok:
				t.Error("Serve still running after refusing")
			case err == nil:
				t.Error("Serve returned nil for a refused connection, want an error")
			}
			if n := r.h.vlog.count(); n != 0 {
				t.Errorf("Attempt ran (%d proof checks) for a refused connection", n)
			}
			if n := len(spy.persisted()); n != 0 {
				t.Errorf("Persist called %d times for a refused connection", n)
			}
			if !r.h.w.IsOpen() {
				t.Error("window closed by a refused connection")
			}
		})
	}

	t.Run("control: the unwrapped pairing connection reaches Attempt", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		runServe(t, c.srv, serveDefault(c.srv, r.h.w, newPersistSpy(), log))
		resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: r.proofFor(t, c, testLabel)}))
		wantStatus(t, "control", resp, err, pairing.StatusOK)
		if n := r.h.vlog.count(); n != 1 {
			t.Errorf("proof verified %d times, want 1", n)
		}
	})
}

func TestServe_StreamAndFrameDeadlines(t *testing.T) {
	if got := pairing.DefaultServeDeadline(); got != proto.ResponseDeadline {
		t.Errorf("Serve's default deadline = %v, want proto.ResponseDeadline %v", got, proto.ResponseDeadline)
	}
	const d = 400 * time.Millisecond

	t.Run("no stream within the deadline closes the connection", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		run := runServe(t, c.srv, serveWithin(c.srv, r.h.w, newPersistSpy(), log, d))
		c.wantClosedWith(t, "no stream", pairing.CodePairRejected, d+serveWait)
		err, took, ok := run.wait(serveWait)
		switch {
		case !ok:
			t.Error("Serve still running after the stream deadline")
		case err == nil:
			t.Error("Serve returned nil when no stream arrived, want an error")
		case took < d*3/4:
			t.Errorf("Serve gave up after %v, before the %v deadline", took, d)
		}
		if n := r.h.vlog.count(); n != 0 {
			t.Errorf("Attempt ran %d times without a request", n)
		}
	})

	t.Run("a stalled frame ends in a close", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		run := runServe(t, c.srv, serveWithin(c.srv, r.h.w, newPersistSpy(), log, d))
		s := c.openStream(t)
		writeAll(t, s, []byte{pairing.FrameVersion, 0x00}) // version and half the length
		if _, closed, _ := c.waitClosed(d + serveWait); !closed {
			t.Errorf("connection still open %v after a stalled frame", d+serveWait)
		}
		_, took, ok := run.wait(serveWait)
		switch {
		case !ok:
			t.Error("Serve still running after the frame deadline")
		case took < d*3/4:
			t.Errorf("Serve gave up after %v, before the %v deadline", took, d)
		}
		if n := r.h.vlog.count(); n != 0 {
			t.Errorf("Attempt ran %d times for an incomplete frame", n)
		}
	})

	t.Run("a frame completed within the deadline is answered", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		runServe(t, c.srv, serveWithin(c.srv, r.h.w, newPersistSpy(), log, 2*time.Second))
		s := c.openStream(t)
		raw := requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: badProof})
		writeAll(t, s, raw[:2])
		time.Sleep(200 * time.Millisecond)
		writeAll(t, s, raw[2:])
		resp, err := readResponse(s, serveWait)
		wantStatus(t, "slow but timely frame", resp, err, pairing.StatusBadProof)
	})

	t.Run("further streams are reset while the request is served", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		runServe(t, c.srv, serveWithin(c.srv, r.h.w, newPersistSpy(), log, 5*time.Second))
		req := c.openStream(t)
		raw := requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: badProof})
		writeAll(t, req, raw[:1])
		extra := c.openStream(t)
		writeAll(t, extra, []byte{0x00})
		if dl, ok := extra.(deadliner); ok {
			_ = dl.SetReadDeadline(time.Now().Add(serveWait))
		}
		_, err := extra.Read(make([]byte, 1))
		var se *quic.StreamError
		if !errors.As(err, &se) || !se.Remote || uint64(se.ErrorCode) != proto.StreamResetCode {
			t.Errorf("read on a second stream = %v, want a remote stream reset with code %#x", err, proto.StreamResetCode)
		}
		writeAll(t, req, raw[1:])
		resp, err := readResponse(req, serveWait)
		wantStatus(t, "request stream after an extra stream", resp, err, pairing.StatusBadProof)
	})

	t.Run("after answering, the listener closes a peer that stays", func(t *testing.T) {
		routeLeakCheck(t)
		r := newServeRig(t, time.Minute)
		_, log := newLogCapture()
		c := r.dial(t, r.joinKey, transport.ALPNPair)
		run := runServe(t, c.srv, serveWithin(c.srv, r.h.w, newPersistSpy(), log, d))
		resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: badProof}))
		wantStatus(t, "bad proof", resp, err, pairing.StatusBadProof)
		c.wantClosedWith(t, "lingering peer", 0, d+serveWait)
		if _, _, ok := run.wait(serveWait); !ok {
			t.Error("Serve still running after closing a lingering peer")
		}
	})
}

func TestServe_BadFrameAndRequestStatuses(t *testing.T) {
	proof := badProof
	req := func(m, label string, p []byte) pairing.PairRequest {
		return pairing.PairRequest{Method: m, Label: label, Proof: p}
	}
	for _, tc := range []struct {
		name string
		raw  func(t *testing.T) []byte
		want pairing.Status
	}{
		{"tunnel frame version", func(*testing.T) []byte { return []byte{proto.ProtoVersion, 0x00, 0x01, 0xa0} }, pairing.StatusBadHeader},
		{"declared length over the limit", func(*testing.T) []byte { return []byte{pairing.FrameVersion, 0x10, 0x01} }, pairing.StatusBadHeader},
		{"payload is not CBOR", func(t *testing.T) []byte { return frameOf(t, []byte{0xff, 0x00}) }, pairing.StatusBadHeader},
		{"missing method", func(t *testing.T) []byte { return requestFrame(t, req("", testLabel, proof)) }, pairing.StatusBadHeader},
		{"proof of the wrong length", func(t *testing.T) []byte {
			return requestFrame(t, req(pairing.MethodTokenHMACv1, testLabel, proof[:pairing.ProofLength-1]))
		}, pairing.StatusBadHeader},
		{"label too long", func(t *testing.T) []byte {
			return requestFrame(t, req(pairing.MethodTokenHMACv1, strings.Repeat("a", pairing.MaxLabelLen+1), proof))
		}, pairing.StatusBadHeader},
		{"label with a reserved byte", func(t *testing.T) []byte {
			return requestFrame(t, req(pairing.MethodTokenHMACv1, "a#b", proof))
		}, pairing.StatusBadHeader},
		{"unknown method", func(t *testing.T) []byte { return requestFrame(t, req("token-hmac-v9", testLabel, proof)) }, pairing.StatusUnsupportedMethod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routeLeakCheck(t)
			r := newServeRig(t, time.Minute)
			spy := newPersistSpy()
			_, log := newLogCapture()
			c := r.dial(t, r.joinKey, transport.ALPNPair)
			runServe(t, c.srv, serveDefault(c.srv, r.h.w, spy, log))
			resp, err := c.exchange(t, tc.raw(t))
			wantStatus(t, tc.name, resp, err, tc.want)
			if tc.want == pairing.StatusUnsupportedMethod && !strings.Contains(resp.Msg, pairing.MethodTokenHMACv1) {
				t.Errorf("unsupported_method msg %q does not list %q", resp.Msg, pairing.MethodTokenHMACv1)
			}
			if n := r.h.vlog.count(); n != 0 {
				t.Errorf("Attempt ran %d times for a request that does not parse", n)
			}
			if n := len(spy.persisted()); n != 0 {
				t.Errorf("Persist called %d times", n)
			}
			if !r.h.w.IsOpen() {
				t.Error("window closed by a malformed request")
			}
		})
	}
}

// frameOf frames payload as a pairing frame.
func frameOf(t *testing.T, payload []byte) []byte {
	t.Helper()
	var b strings.Builder
	if err := pairing.WriteFrame(&b, payload); err != nil {
		t.Fatalf("frame: %v", err)
	}
	return []byte(b.String())
}

func TestServe_DualStackIPv4ClientBudgetedAsIPv4(t *testing.T) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Skipf("cannot bind the dual-stack wildcard [::]: %v", err)
	}
	routeLeakCheck(t)
	r := newServeRigOn(t, sock, time.Minute)
	if ip := r.lnAddr.(*net.UDPAddr).IP; ip.To4() != nil || !ip.IsUnspecified() {
		sock.Close()
		t.Fatalf("listener bound %v, want the IPv6 wildcard", ip)
	}
	spy := newPersistSpy()
	_, log := newLogCapture()
	c, err := r.tryDial(t, r.joinKey, transport.ALPNPair)
	if err != nil {
		t.Skipf("the [::] socket does not accept IPv4 clients here (IPV6_V6ONLY?): %v", err)
	}
	ra, ok := remoteOf(c.srv).(*net.UDPAddr)
	if !ok || ra.AddrPort().Addr().Unmap() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("listener sees the client as %v, want 127.0.0.1 (possibly IPv4-mapped)", remoteOf(c.srv))
	}
	runServe(t, c.srv, serveDefault(c.srv, r.h.w, spy, log))
	resp, err := c.exchange(t, requestFrame(t, pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: testLabel, Proof: badProof}))
	wantStatus(t, "bad proof over the dual-stack socket", resp, err, pairing.StatusBadProof)
	if st := r.h.w.Status(); st.SourcesTracked != 1 {
		t.Fatalf("SourcesTracked = %d after one attempt, want 1", st.SourcesTracked)
	}

	// The wire attempt was charged to 127.0.0.1/32: four more failures from
	// that address exhaust it, and even a valid proof is then refused.
	v4 := netip.MustParseAddr("127.0.0.1")
	for i := 2; i <= wantBudget; i++ {
		if st := r.h.w.Attempt(v4, badProof, testEKM); st != pairing.StatusBadProof {
			t.Fatalf("failure %d from 127.0.0.1 = %v, want bad_proof", i, st)
		}
	}
	valid := validProof(t, r.h.w)
	if st := r.h.w.Attempt(v4, valid, testEKM); st != pairing.StatusRateLimited {
		t.Errorf("attempt %d from 127.0.0.1 = %v, want rate_limited: the wire attempt was not budgeted as 127.0.0.1/32", wantBudget+1, st)
	}
	if st := r.h.w.Status(); st.SourcesTracked != 1 || st.SourcesExhausted != 1 {
		t.Errorf("Status = %+v, want one tracked, exhausted source", st)
	}
	if st := r.h.w.Attempt(netip.MustParseAddr("127.0.0.2"), valid, testEKM); st != pairing.StatusOK {
		t.Errorf("valid proof from 127.0.0.2 = %v, want ok (a neighbouring /32 is unaffected)", st)
	}
}
