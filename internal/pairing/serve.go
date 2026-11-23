package pairing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// Persister records a pin admitted by a pairing window.
type Persister interface {
	Persist(pin, label string, from netip.AddrPort) error
}

// Confirmer is optional: a Persister that implements it is told after the ok
// response was written, to mark the pin confirmed.
type Confirmer interface {
	Confirm(pin string) error
}

// serveOpts are Serve's injectable dependencies.
type serveOpts struct {
	// deadline bounds each wait: for the request stream, for the request
	// frame, for writing the response and for the peer to hang up after it.
	deadline time.Duration
	// refusalLinger: placeholder, not used yet.
	refusalLinger time.Duration
	// onShutdown, if set, runs in the shutdown watcher once the caller's ctx
	// ended, before the watcher acts (test hook).
	onShutdown func()
}

// defaultServeOpts returns the production dependencies.
func defaultServeOpts() serveOpts { return serveOpts{deadline: proto.ResponseDeadline} }

// streamDeadliner is the deadline control the transport's own streams have
// beyond transport.Stream.
type streamDeadliner interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// pairPeer is what Serve needs to know about the joiner before reading.
type pairPeer struct {
	pin  string
	from netip.AddrPort
	ekm  transport.EKMProvider
}

// ErrSavedNotAcknowledged is wrapped by Serve's error when the joiner's pin
// was saved (it is authorized, unconfirmed) but the ok answer could not be
// written. Confirm is not called; the operator may remove the pin.
var ErrSavedNotAcknowledged = errors.New("pairing: serve: client saved (unconfirmed) but not told ok")

// Serve handles one pairing exchange on conn against w: it reads one request,
// lets w.Attempt judge it, records an admitted pin through p before answering
// ok, and tells p's Confirmer (if any) after the answer. A request that
// arrives after w closed is still read and answered window_closed by Attempt,
// so a handshake that began while the window was open is never served late.
//
// A connection Serve cannot handle - wrong ALPN, missing keying material,
// remote address or peer certificate, nil w, p or log, no request stream in
// time - is closed with CodePairRejected without calling Attempt or Persist.
// Further streams are reset while Serve runs. After answering, Serve waits for
// the peer to close (bounded) and closes with code 0. ctx ending closes conn.
//
// Serve returns nil only when the joiner was told ok. Logs carry at most the
// pin's 8-character prefix, never the proof, keying material or secret.
func Serve(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger) error {
	return serveWith(ctx, conn, w, p, log, defaultServeOpts())
}

// serveWith is Serve with injectable dependencies.
func serveWith(ctx context.Context, conn transport.Conn, w *Window, p Persister, log *slog.Logger, o serveOpts) error {
	if conn == nil {
		return errors.New("pairing: serve: nil connection")
	}
	peer, err := checkPeer(conn, w, p, log)
	if err != nil {
		reject(conn)
		return err
	}

	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(done)
		cancel()
		wg.Wait()
	}()
	// Shutdown (the caller's ctx ending) closes the connection, which aborts
	// any read or write below instead of waiting out its deadline.
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-parent.Done():
			if o.onShutdown != nil {
				o.onShutdown()
			}
			reject(conn)
		case <-done:
		}
	}()

	s, err := acceptRequestStream(ctx, conn, o.deadline)
	if err != nil {
		reject(conn)
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		resetFurtherStreams(ctx, conn)
	}()
	dl, ok := s.(streamDeadliner)
	if !ok {
		reject(conn)
		return fmt.Errorf("pairing: serve: stream %T has no deadlines", s)
	}

	st, label, err := judge(s, dl, peer, w, o.deadline)
	if err != nil {
		reject(conn)
		return err
	}
	if st == StatusOK {
		if err := p.Persist(peer.pin, label, peer.from); err != nil {
			// The window already closed on the valid proof and is not reopened:
			// the joiner is refused and the operator opens a new window.
			log.Error("pairing: could not save the paired client; pairing window is now closed; open a new one",
				"peer", pinPrefix(peer.pin), "from", peer.from.String(), "err", err)
			st = StatusWindowClosed
		}
	}

	werr := writeResponse(s, dl, st, o.deadline)
	if st == StatusOK && werr == nil {
		log.Info("pairing: client paired", "peer", pinPrefix(peer.pin), "label", label, "from", peer.from.String())
		if c, ok := p.(Confirmer); ok {
			if err := c.Confirm(peer.pin); err != nil {
				log.Warn("pairing: could not mark the paired client confirmed; it is authorized either way",
					"peer", pinPrefix(peer.pin), "err", err)
			}
		}
	} else if st != StatusOK {
		log.Info("pairing: request refused", "peer", pinPrefix(peer.pin), "from", peer.from.String(), "status", st.String())
	}

	linger(ctx, conn, o.deadline)
	_ = conn.CloseWithError(0, "")
	switch {
	case werr != nil:
		return fmt.Errorf("pairing: serve: write response: %w", werr)
	case st != StatusOK:
		return fmt.Errorf("pairing: serve: request refused: %v", st)
	}
	return nil
}

// checkPeer verifies Serve's preconditions and extracts the joiner's pin and
// UDP source.
func checkPeer(conn transport.Conn, w *Window, p Persister, log *slog.Logger) (pairPeer, error) {
	if w == nil || p == nil || log == nil {
		return pairPeer{}, errors.New("pairing: serve: nil window, persister or logger")
	}
	if a, ok := conn.(transport.ALPNProvider); !ok || a.NegotiatedProtocol() != transport.ALPNPair {
		return pairPeer{}, errors.New("pairing: serve: connection did not negotiate the pairing protocol")
	}
	ekm, ok := conn.(transport.EKMProvider)
	if !ok {
		return pairPeer{}, errors.New("pairing: serve: connection exports no keying material")
	}
	ra, ok := conn.(transport.RemoteAddrProvider)
	if !ok {
		return pairPeer{}, errors.New("pairing: serve: connection reports no remote address")
	}
	ua, ok := ra.RemoteAddr().(*net.UDPAddr)
	if !ok || ua == nil {
		return pairPeer{}, errors.New("pairing: serve: remote address is not UDP")
	}
	from := ua.AddrPort()
	if !from.Addr().IsValid() {
		return pairPeer{}, errors.New("pairing: serve: remote UDP address is invalid")
	}
	certs := conn.PeerCertificates()
	if len(certs) == 0 || certs[0] == nil {
		return pairPeer{}, errors.New("pairing: serve: no peer certificate")
	}
	return pairPeer{pin: identity.PinFromCert(certs[0]), from: from, ekm: ekm}, nil
}

// acceptRequestStream waits at most d for the joiner's request stream.
func acceptRequestStream(ctx context.Context, conn transport.Conn, d time.Duration) (transport.Stream, error) {
	actx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	s, err := conn.AcceptStream(actx)
	if err != nil {
		return nil, fmt.Errorf("pairing: serve: no request stream: %w", err)
	}
	return s, nil
}

// resetFurtherStreams resets every stream the peer opens until ctx ends:
// a pairing conversation carries exactly one.
func resetFurtherStreams(ctx context.Context, conn transport.Conn) {
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		s.Reset(proto.StreamResetCode)
	}
}

// judge reads one request within d and returns the status to answer and the
// request label. An error means the exchange ends without an answer.
func judge(s transport.Stream, dl streamDeadliner, peer pairPeer, w *Window, d time.Duration) (Status, string, error) {
	if err := dl.SetReadDeadline(time.Now().Add(d)); err != nil {
		return 0, "", fmt.Errorf("pairing: serve: set read deadline: %w", err)
	}
	req, st := readRequest(s)
	if st != StatusOK {
		return st, "", nil
	}
	ekm, err := peer.ekm.ExportKeyingMaterial(EKMLabel, ExporterContext(req.Label), EKMLength)
	if err != nil {
		return 0, "", fmt.Errorf("pairing: serve: export keying material: %w", err)
	}
	return w.Attempt(peer.from.Addr(), req.Proof, ekm), req.Label, nil
}

// readRequest reads and parses one request. A status other than StatusOK is
// the answer for a request that cannot be judged: bad_header for a frame that
// fails or stalls, else the parse error's status.
func readRequest(s transport.Stream) (PairRequest, Status) {
	payload, err := ReadFrame(s)
	if err != nil {
		return PairRequest{}, StatusBadHeader
	}
	req, err := ParsePairRequest(payload)
	return req, StatusForParseError(err)
}

// writeResponse answers st within d and closes the stream's send side.
func writeResponse(s transport.Stream, dl streamDeadliner, st Status, d time.Duration) error {
	resp := PairResponse{Status: st}
	if st == StatusUnsupportedMethod {
		resp.Msg = "supported methods: " + MethodTokenHMACv1
	}
	payload, err := resp.Marshal()
	if err != nil {
		return err
	}
	if err := dl.SetWriteDeadline(time.Now().Add(d)); err != nil {
		return err
	}
	if err := WriteFrame(s, payload); err != nil {
		return err
	}
	return s.Close()
}

// linger gives the peer up to d to read the answer and hang up.
func linger(ctx context.Context, conn transport.Conn, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
	case <-t.C:
	}
}

// reject closes conn as not served.
func reject(conn transport.Conn) { _ = conn.CloseWithError(CodePairRejected, "") }

// pinPrefix is the part of a pin that logs may carry.
func pinPrefix(pin string) string {
	if len(pin) > 8 {
		return pin[:8]
	}
	return pin
}
