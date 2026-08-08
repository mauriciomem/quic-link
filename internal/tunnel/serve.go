// Package tunnel wires together the transport layer and local TCP services.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// ServeOpts carries optional parameters for Serve. The zero value is valid
// and produces the same behaviour as before ServeOpts was introduced.
type ServeOpts struct {
	// WarnKeyAgeDays, when > 0, causes the agent to log a rotation advisory
	// when a connecting client's self-reported key age exceeds the threshold.
	// The advisory is informational only and never closes or rejects a session.
	WarnKeyAgeDays int
	// OwnPin is this endpoint's own identity. When set, a peer presenting it is
	// refused: the two ends would be sharing one keypair, so neither could tell
	// which role the other was playing. Leave empty to skip the check.
	OwnPin string
	// ControlPolicy decides whether an authenticated peer may invoke a given
	// control-plane RPC (Ping, GetStatus, and whatever is added later). Nil
	// defaults to allow-all, matching the router's own default posture for
	// data-plane authorization; it exists so a future per-key policy is a
	// value swap here, not new plumbing through the control stream.
	ControlPolicy control.Policy
	// Version is reported to a client's GetStatus call as this agent's own
	// build version. Empty means unknown, not a build defect — an agent
	// built without version stamping still serves GetStatus, it just has
	// nothing informative to say for this field.
	Version string
	// StartedAt is reported to a client's GetStatus call as StartedUnixMs.
	// The zero value means unknown; GetStatus leaves the field at zero
	// rather than reporting a clearly-wrong timestamp for it.
	StartedAt time.Time
}

// controlRouteSource adapts *router.Router to control.RouteSource,
// converting router.RouteDetail into control.RouteDetail. This is the one
// conversion boundary allowed to know about both types: internal/control
// must not import internal/router (a control-plane RPC and a data-plane
// dial target are two different assets guarded by two different
// boundaries), so the adapter lives here, in the one package that already
// imports both.
type controlRouteSource struct {
	rtr *router.Router
}

func (s controlRouteSource) RouteDetails() []control.RouteDetail {
	details := s.rtr.RouteDetails()
	out := make([]control.RouteDetail, len(details))
	for i, d := range details {
		out[i] = control.RouteDetail{Name: d.Name, Address: d.Address, Builtin: d.Builtin}
	}
	return out
}

// SameIdentityAsPeer reports whether the peer is using our own identity. It is
// the one role confusion that survives the handshake, because a peer holding
// any other key is already refused by the pin check.
func SameIdentityAsPeer(ownPin string, peer router.Identity) bool {
	return ownPin != "" && peer.Pin == ownPin
}

// RoleMismatchCode is sent when a peer authenticates but is playing the same
// role we are, which means the two ends are configured with one identity
// between them. Under pinning a peer that holds the wrong key is refused during
// the handshake, so this is the one role confusion that can get far enough to
// need saying out loud.
const RoleMismatchCode = 0x02

const (
	// controlOpenDeadline bounds how long after a session is established the
	// client may take to open its control stream. Past it, the agent closes
	// the session with 0x03.
	controlOpenDeadline = 5 * time.Second
	// agentVersionMsg is carried in the control stream's ok response.
	// TODO: replace with the build version once it is wired through.
	agentVersionMsg = "quic-link agent"
)

// Serve accepts QUIC connections from ln and, for every stream opened by a
// client, reads a protocol-v1 header, resolves and authorizes the named target
// through rtr, replies with a response frame, and (on success) bidirectionally
// proxies data to the resolved address. It runs until ctx is cancelled or ln
// is closed. opts carries optional per-server settings; pass zero value if not
// needed.
func Serve(ctx context.Context, ln transport.Listener, rtr *router.Router, opts ...ServeOpts) error {
	var opt ServeOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go serveConn(ctx, conn, rtr, opt)
	}
}

// ServeConn handles every stream on one already-established connection, whether
// this side accepted it or opened it. Nothing below this point depends on which
// end opened the transport: the peer identity comes from the connection's own
// certificate, and the route table is enforced the same way either way.
//
// It returns when the connection is gone, so a caller that opened the
// connection can use it as the body of its own reconnect loop.
func ServeConn(ctx context.Context, conn transport.Conn, rtr *router.Router, opts ...ServeOpts) {
	var opt ServeOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	serveConn(ctx, conn, rtr, opt)
}

// serveConn derives the peer identity once and handles all streams on a
// single accepted QUIC connection. It also enforces the control-stream open
// deadline: if the client does not open a control stream within
// controlOpenDeadline, the session is closed with 0x03.
func serveConn(ctx context.Context, conn transport.Conn, rtr *router.Router, opt ServeOpts) {
	peer, err := router.IdentityFromCerts(conn.PeerCertificates())
	if err != nil {
		// Should be unreachable: the pinning handshake already requires a client
		// certificate, so a peer without one never completes a connection. Kept
		// as defense-in-depth.
		_ = conn.CloseWithError(0x02, "no peer identity")
		return
	}
	if SameIdentityAsPeer(opt.OwnPin, peer) {
		slog.Error("peer is using our own identity; refusing the session. "+
			"Both ends are configured with the same key, so neither can tell which role the other is playing: "+
			"generate a separate key for each end",
			"role", "agent", "peer", peer.Short())
		_ = conn.CloseWithError(RoleMismatchCode, "peer presented our own identity")
		return
	}

	sessionStart := time.Now()
	slog.Info("session established", "role", "agent", "peer", peer.Short())

	cs := &controlState{}
	openTimer := time.AfterFunc(controlOpenDeadline, func() {
		if !cs.isOpen() {
			_ = conn.CloseWithError(0x03, "control stream not opened within deadline")
		}
	})
	defer openTimer.Stop()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Connection closed or ctx cancelled; stop accepting streams.
			// When the context is cancelled (agent shutting down), send a
			// CONNECTION_CLOSE to the peer instead of waiting for the 60s
			// idle timeout. Without this, the peer would wait the full
			// MaxIdleTimeout before detecting the drop.
			if ctx.Err() != nil {
				_ = conn.CloseWithError(0, "agent shutting down")
			}
			return
		}
		go func() {
			if err := serveStream(ctx, conn, stream, peer, rtr, cs, openTimer, sessionStart, opt); err != nil {
				slog.Warn("stream handler error", "err", err)
			}
		}()
	}
}

// serveStream reads the protocol-v1 header and dispatches: a control stream to
// serveControl, otherwise a data stream resolved and authorized via rtr, then
// on status 0 spliced to the dialed connection. pipe() owns the lifetime of
// both stream and svc once splicing begins.
func serveStream(
	ctx context.Context,
	conn transport.Conn,
	stream transport.Stream,
	peer router.Identity,
	rtr *router.Router,
	cs *controlState,
	openTimer *time.Timer,
	sessionStart time.Time,
	opt ServeOpts,
) error {
	h, err := proto.ReadHeader(stream)
	if err != nil {
		return replyHeaderError(stream, err)
	}

	if h.Kind == proto.KindControl {
		return serveControl(ctx, conn, stream, peer, h, rtr, cs, openTimer, sessionStart, opt)
	}

	// Extract the correlation id stamped by the client. It may be absent for
	// older or third-party clients; tolerate the empty string silently.
	reqid := h.Meta["reqid"]

	svc, err := rtr.Dial(ctx, peer, h)
	if err != nil {
		slog.Debug("stream dial failed",
			"kind", h.Kind,
			"target", h.Target,
			"reqid", reqid,
		)
		return replyDialError(stream, h, err)
	}

	if err := proto.WriteResponse(stream, proto.Response{Status: proto.StatusOK}); err != nil {
		_ = svc.Close()
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("write ok response: %w", err)
	}

	slog.Debug("stream header exchange complete",
		"kind", h.Kind,
		"target", h.Target,
		"reqid", reqid,
		"status", proto.StatusOK.String(),
	)

	start := time.Now()
	slog.Info("stream proxying to service", "peer", peer.Short(), "target", h.Target, "reqid", reqid)
	// pipe closes both stream and svc when done.
	pipe(stream, svc)
	slog.Info("stream closed",
		"peer", peer.Short(),
		"target", h.Target,
		"duration", time.Since(start).Round(time.Millisecond),
		"reqid", reqid,
	)
	return nil
}

// serveControl handles the single per-session control stream: it
// validates the control proto version, enforces exactly-one-per-session, replies
// ok, logs an advisory when a client reports an over-age key, and then serves
// gRPC until the stream closes — at which point the whole session is torn down
// (control-stream closure is session death). sessionStart is the time the
// outer session was accepted, used to compute session duration on disconnect.
// rtr supplies the route table for a GetStatus call, wrapped in an adapter
// so internal/control never has to import internal/router itself.
func serveControl(
	ctx context.Context,
	conn transport.Conn,
	stream transport.Stream,
	peer router.Identity,
	h proto.Header,
	rtr *router.Router,
	cs *controlState,
	openTimer *time.Timer,
	sessionStart time.Time,
	opt ServeOpts,
) error {
	if h.Meta["proto"] != "1" {
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnsupportedVersion,
			Msg:    `control proto must be "1"`,
		})
		_ = stream.Close()
		_ = conn.CloseWithError(0x04, "unsupported control proto")
		return nil
	}
	if !cs.markOpen() {
		// A control stream is already open on this session.
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusBadHeader,
			Msg:    "control stream already open",
		})
		_ = stream.Close()
		return nil
	}
	openTimer.Stop()

	// Log an advisory when the client reports its key creation time and the
	// agent has a warn threshold configured. This is self-asserted data from
	// an already-authenticated peer — it is never used to gate the session.
	if raw, ok := h.Meta["key_created"]; ok && opt.WarnKeyAgeDays > 0 {
		if t, err := time.Parse(time.RFC3339, raw); err != nil {
			slog.Debug("peer key_created field is not valid RFC3339; ignoring",
				"peer", peer.Short(), "raw", raw,
			)
		} else {
			ageDays := int(time.Since(t).Hours() / 24)
			if ageDays > opt.WarnKeyAgeDays {
				slog.Warn("peer key is over the rotation age threshold (advisory only; session continues)",
					"peer", peer.Short(),
					"key_age_days", ageDays,
					"warn_key_age_days", opt.WarnKeyAgeDays,
				)
			}
		}
	}

	if err := proto.WriteResponse(stream, proto.Response{Status: proto.StatusOK, Msg: agentVersionMsg}); err != nil {
		stream.Reset(proto.StreamResetCode)
		_ = conn.CloseWithError(0x03, "control response write failed")
		return fmt.Errorf("control: write ok: %w", err)
	}

	slog.Info("control stream opened", "role", "agent", "peer", peer.Short())
	// Serve gRPC until the control stream dies; then the session is dead.
	controlOpts := control.ServeOpts{
		Routes:    controlRouteSource{rtr: rtr},
		Version:   opt.Version,
		StartedAt: opt.StartedAt,
	}
	_ = control.Serve(ctx, stream, control.PeerIdentity{Pin: peer.Pin}, opt.ControlPolicy, controlOpts)
	slog.Info("client disconnected",
		"role", "agent",
		"peer", peer.Short(),
		"session_duration", time.Since(sessionStart).Round(time.Millisecond),
	)
	_ = conn.CloseWithError(0x00, "control stream closed")
	return nil
}

// controlState tracks whether this session's one-per-session control stream has
// been opened, so the open deadline can be cancelled and a duplicate refused.
type controlState struct {
	mu   sync.Mutex
	open bool
}

// markOpen records the control stream as open, returning true only the first
// time (a second call — a duplicate control stream — returns false).
func (c *controlState) markOpen() (firstTime bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		return false
	}
	c.open = true
	return true
}

func (c *controlState) isOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.open
}

// UnknownTargetMessage returns the exact wording used for an unknown-target
// refusal (the Msg carried alongside proto.StatusUnknownTarget). It is
// exported so a client-side caller — fwd's startup preflight, specifically —
// can recognize this one specific case among the several distinct causes
// grouped under exit code 5 (unknown target, dial failure, draining) without
// guessing at the agent's free-text message from the client side. Changing
// this string's wording is not a wire-protocol change: Response.Msg has
// always been implementation-defined free text, not a field whose bytes or
// semantics are part of the frame layout.
func UnknownTargetMessage(target string) string {
	return unknownTargetMessage(target)
}

func unknownTargetMessage(target string) string {
	return fmt.Sprintf("no target %q", target)
}

// destinationOf names what a stream asked for, whichever way it asked.
func destinationOf(h proto.Header) string {
	if h.Kind == proto.KindHTTP {
		return h.Host
	}
	return h.Target
}

// replyDialError maps a router.Dial failure to the protocol response and
// returns an error for logging. Expected refusals (unknown target,
// unauthorized) return nil so they do not log loudly; a genuine dial failure is
// wrapped and returned.
func replyDialError(stream transport.Stream, h proto.Header, err error) error {
	switch {
	case errors.Is(err, router.ErrUnknownTarget):
		// A stream that named a host has no target, so blaming an empty target
		// would send the operator looking in the wrong table. The tcp wording is
		// unchanged, because the client recognises it.
		msg := unknownTargetMessage(h.Target)
		if h.Kind == proto.KindHTTP {
			msg = fmt.Sprintf("no service is published as %q", h.Host)
		}
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnknownTarget,
			Msg:    msg,
		})
		_ = stream.Close()
		return nil
	case errors.Is(err, router.ErrUnauthorized):
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnauthorized,
			Msg:    fmt.Sprintf("not authorized for %q", destinationOf(h)),
		})
		_ = stream.Close()
		return nil
	default:
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusDialFailed,
			Msg:    err.Error(),
		})
		_ = stream.Close()
		return fmt.Errorf("dial target %q: %w", h.Target, err)
	}
}

// replyHeaderError maps a header read/parse failure to the protocol behavior
// and returns the error for logging.
func replyHeaderError(stream transport.Stream, err error) error {
	switch {
	case errors.Is(err, proto.ErrFrameTooLarge):
		// Oversized frame: reset the stream, send no response.
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("header: %w", err)
	case errors.Is(err, proto.ErrUnsupportedVersion):
		// Unsupported version: acceptor replies status 6.
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusUnsupportedVersion,
			Msg:    "unsupported protocol version; rebuild the client",
		})
		_ = stream.Close()
		return fmt.Errorf("header: %w", err)
	case errors.Is(err, proto.ErrBadHeader):
		// Malformed or missing header fields: status 5.
		_ = proto.WriteResponse(stream, proto.Response{
			Status: proto.StatusBadHeader,
			Msg:    err.Error(),
		})
		_ = stream.Close()
		return fmt.Errorf("header: %w", err)
	default:
		// I/O error before a full header arrived (e.g. peer vanished).
		stream.Reset(proto.StreamResetCode)
		return fmt.Errorf("read header: %w", err)
	}
}

// closeWrite half-closes the write side of c, propagating a clean EOF as a FIN.
// *net.TCPConn and *net.UnixConn expose CloseWrite(); a transport.Stream's
// Close() closes only its send direction, so Close() is the correct
// write-half-close for streams.
func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// resetConn tears a connection down abruptly (a reset stays a reset).
// SetLinger(0) makes a TCP Close() emit RST; a transport.Stream is reset with
// the QUIC stream reset code. A unix socket has no RST, so the default plain
// Close() is the closest equivalent.
func resetConn(c io.Closer) {
	switch v := c.(type) {
	case *net.TCPConn:
		_ = v.SetLinger(0)
		_ = v.Close()
	case transport.Stream:
		v.Reset(proto.StreamResetCode)
	default:
		_ = c.Close()
	}
}

// Pipe bidirectionally copies between a and b. A clean EOF in one direction
// becomes a write-half-close on the peer so the other direction keeps
// flowing — this is what lets scp, git, and request/response protocols finish
// instead of truncating. Both ends are fully released only after both
// directions complete. It is exported so callers outside this package (e.g. a
// stdio bridge in cmd/) can reuse the same half-close semantics without
// duplicating the reset/FIN logic.
func Pipe(a, b io.ReadWriteCloser) {
	pipe(a, b)
}

// pipe is the unexported implementation shared by Pipe and the internal callers
// in this package.
func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		if _, err := io.Copy(b, a); err != nil {
			resetConn(b) // abrupt failure: reset, don't FIN
		} else {
			closeWrite(b) // clean EOF from a: no more writes are coming to b
		}
		done <- struct{}{}
	}()
	go func() {
		if _, err := io.Copy(a, b); err != nil {
			resetConn(a)
		} else {
			closeWrite(a)
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	// Both directions finished; release resources (idempotent; errors ignored).
	_ = a.Close()
	_ = b.Close()
}
