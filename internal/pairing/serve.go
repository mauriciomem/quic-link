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
	// deadline bounds the whole exchange: request stream, request frame and
	// response share one deadline set when Serve starts. It also bounds the
	// wait for the peer to hang up after an ok.
	deadline time.Duration
	// refusalLinger bounds the wait for the peer to hang up after any answer
	// other than ok.
	refusalLinger time.Duration
	// onShutdown, if set, runs in the shutdown watcher once the caller's ctx
	// ended, before the watcher acts (test hook).
	onShutdown func()
}

// defaultServeOpts returns the production dependencies.
func defaultServeOpts() serveOpts {
	return serveOpts{deadline: proto.ResponseDeadline, refusalLinger: refusalLinger}
}

// refusalLinger is how long Serve waits for a refused peer to hang up.
const refusalLinger = time.Second

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
// Further streams are reset while Serve runs.
//
// One deadline (proto.ResponseDeadline) bounds the request stream, the request
// and the response together. After an ok Serve waits up to that long for the
// peer to hang up; after any other answer, one second. Then it closes with
// code 0. ctx ending closes conn while the request is being read, and is
// ignored once an admitted pin is being saved (see ErrSavedNotAcknowledged).
//
// Serve returns nil only when the joiner was told ok. When the pin was saved
// but the answer could not be written, it logs a WARN and returns an error
// wrapping ErrSavedNotAcknowledged; the pin stays authorized and unconfirmed.
// Once a valid proof is being saved, ctx ending no longer closes conn: the
// joiner is answered ok. Logs carry at most the pin's 8-character prefix,
// never the proof, keying material or secret.
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

	end := time.Now().Add(o.deadline)

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
	// any read or write below instead of waiting out its deadline - until the
	// commit point: once an admitted pin is being saved, the joiner is
	// answered ok instead.
	var (
		sm        sync.Mutex
		committed bool // the main path decided to save; shutdown no longer closes conn
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-parent.Done():
			if o.onShutdown != nil {
				o.onShutdown()
			}
			sm.Lock()
			if !committed {
				reject(conn)
			}
			sm.Unlock()
		case <-done:
		}
	}()

	s, err := acceptRequestStream(ctx, conn, end)
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

	st, label, err := judge(s, dl, peer, w, end)
	if err != nil {
		reject(conn)
		return err
	}
	if st == StatusOK {
		// The commit point. parent is checked here, under the watcher's lock,
		// because the watcher may not have run yet; when it has, parent has
		// ended too.
		sm.Lock()
		shutDown := parent.Err() != nil
		committed = !shutDown
		sm.Unlock()
		if shutDown {
			reject(conn)
			log.Warn("pairing: shutting down; the paired client was not saved; pairing window is now closed; open a new one",
				"peer", pinPrefix(peer.pin), "from", peer.from.String())
			return errors.New("pairing: serve: shut down before the admitted pin was saved")
		}
		if err := p.Persist(peer.pin, label, peer.from); err != nil {
			// The window already closed on the valid proof and is not reopened:
			// the joiner is refused and the operator opens a new window.
			log.Error("pairing: could not save the paired client; pairing window is now closed; open a new one",
				"peer", pinPrefix(peer.pin), "from", peer.from.String(), "err", err)
			st = StatusWindowClosed
		}
	}

	werr := writeResponse(s, dl, st, end)
	switch {
	case st == StatusOK && werr == nil:
		log.Info("pairing: client paired", "peer", pinPrefix(peer.pin), "label", label, "from", peer.from.String())
		if c, ok := p.(Confirmer); ok {
			if err := c.Confirm(peer.pin); err != nil {
				log.Warn("pairing: could not mark the paired client confirmed; it is authorized either way",
					"peer", pinPrefix(peer.pin), "err", err)
			}
		}
	case st == StatusOK: // saved, but the answer was not written
		log.Warn("pairing: client saved but not told ok; it is authorized (unconfirmed); remove it if unexpected",
			"peer", pinPrefix(peer.pin), "label", label, "from", peer.from.String(), "err", werr)
	default:
		log.Info("pairing: request refused", "peer", pinPrefix(peer.pin), "from", peer.from.String(), "status", st.String())
	}

	switch {
	case werr != nil:
		// Nothing was delivered; there is nothing to wait for.
	case st == StatusOK:
		// After the commit point shutdown does not cut the ok linger short.
		linger(nil, conn, o.deadline)
	default:
		linger(ctx.Done(), conn, o.refusalLinger)
	}
	_ = conn.CloseWithError(0, "")
	switch {
	case st == StatusOK && werr != nil:
		return fmt.Errorf("%w: write response: %w", ErrSavedNotAcknowledged, werr)
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
	from, err := udpSource(conn)
	if err != nil {
		return pairPeer{}, err
	}
	certs := conn.PeerCertificates()
	if len(certs) == 0 || certs[0] == nil {
		return pairPeer{}, errors.New("pairing: serve: no peer certificate")
	}
	return pairPeer{pin: identity.PinFromCert(certs[0]), from: from, ekm: ekm}, nil
}

// udpSource is c's UDP source address.
func udpSource(c transport.Conn) (netip.AddrPort, error) {
	ra, ok := c.(transport.RemoteAddrProvider)
	if !ok {
		return netip.AddrPort{}, errors.New("pairing: serve: connection reports no remote address")
	}
	ua, ok := ra.RemoteAddr().(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}, errors.New("pairing: serve: remote address is not UDP")
	}
	from := ua.AddrPort()
	if !from.Addr().IsValid() {
		return netip.AddrPort{}, errors.New("pairing: serve: remote UDP address is invalid")
	}
	return from, nil
}

// acceptRequestStream waits until end for the joiner's request stream.
func acceptRequestStream(ctx context.Context, conn transport.Conn, end time.Time) (transport.Stream, error) {
	actx, cancel := context.WithDeadline(ctx, end)
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

// judge reads one request by end and returns the status to answer and the
// request label. An error means the exchange ends without an answer.
func judge(s transport.Stream, dl streamDeadliner, peer pairPeer, w *Window, end time.Time) (Status, string, error) {
	if err := dl.SetReadDeadline(end); err != nil {
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

// writeResponse answers st by end and closes the stream's send side.
func writeResponse(s transport.Stream, dl streamDeadliner, st Status, end time.Time) error {
	resp := PairResponse{Status: st}
	if st == StatusUnsupportedMethod {
		resp.Msg = "supported methods: " + MethodTokenHMACv1
	}
	payload, err := resp.Marshal()
	if err != nil {
		return err
	}
	if err := dl.SetWriteDeadline(end); err != nil {
		return err
	}
	if err := WriteFrame(s, payload); err != nil {
		return err
	}
	return s.Close()
}

// linger gives the peer up to d to read the answer and hang up; it also ends
// when stop does (a nil stop never does).
func linger(stop <-chan struct{}, conn transport.Conn, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-conn.Context().Done():
	case <-stop:
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
