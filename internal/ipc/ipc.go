// Package ipc implements the local unix-socket IPC between quic-link verbs
// (status, ssh, fwd, docker-env) and the daemon process. The socket carries
// two kinds of traffic:
//
//   - RPC (kind="rpc"): small request/response messages. The client sends one
//     Request, the server replies with one Response, then the connection closes.
//
//   - Attach (kind="attach"): the daemon opens a QUIC stream for the named
//     server/target, sends an attach-ack Response, and then splices the socket
//     connection directly to the QUIC stream. The splice is wired in a later
//     slice; currently the server returns a stub ack.
//
// All frames use CBOR with a version|length|payload envelope that mirrors the
// wire protocol's philosophy without sharing its bytes or version space. The
// socket_schema field in every frame serves stale-daemon detection: a schema
// mismatch is rejected before any action is taken and is never best-effort
// parsed.
//
// Goroutine ownership: the Server starts one goroutine per accepted connection
// (per-conn handler). Each handler exits after the request/response pair (RPC)
// or when the splice ends (attach). No goroutines outlive Server.Close().
package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// SocketSchema is the IPC socket schema version. Every Request and Response
// carries this value. A mismatch (including a zero value, which signals a
// client that predates schema versioning) causes the receiver to reject the
// request with a framed error and take no further action. This is a local
// breaking change — bumping it requires restarting the daemon — and is
// entirely separate from the QUIC wire protocol version.
const SocketSchema = 1

// maxFrameSize is the maximum allowed IPC frame payload in bytes. The length
// prefix is rejected before allocating a buffer if it exceeds this limit,
// protecting the daemon from a trivially large allocation. 64 KiB is ample
// for any status snapshot or attach request.
const maxFrameSize = 64 * 1024

// openReadDeadline is applied to the opening Request read only. After the
// header is read the deadline is cleared. A live attach splice may legitimately
// idle for hours, so no deadline is imposed after the initial handshake.
const openReadDeadline = 5 * time.Second

// ipcFrameVersion is the single-byte version prefix for IPC frames. It is
// distinct from the QUIC wire proto version so a stray QUIC connection that
// stumbles onto the socket path produces a clear version-mismatch error rather
// than silently misparsing.
const ipcFrameVersion = 0x01

// encMode pins definition-order (SortNone) CBOR encoding so frames are
// byte-stable. The wire protocol uses the same approach.
var encMode cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortNone}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("ipc: build CBOR encode mode: %v", err))
	}
	encMode = em
}

// ---- Sentinel errors ---------------------------------------------------------

// ErrDaemonAbsent is returned when a CLI verb cannot connect to the daemon
// socket (ECONNREFUSED or no listener). The caller should print a remedy
// before returning this error so the operator knows how to start the daemon.
var ErrDaemonAbsent = errors.New("daemon not running")

// ErrSchemaMismatch is returned when the daemon's socket_schema does not match
// the CLI's expected value. The daemon is present but incompatible; restarting
// it is the remedy. Shares exit code 3 with ErrDaemonAbsent because both
// conditions mean "daemon not usable right now."
var ErrSchemaMismatch = errors.New("daemon socket schema mismatch")

// ErrOwnerRunning is returned when a daemon or connect invocation finds that
// a conforming owner already holds the socket and answered a status probe.
// The operator should use "quic-link status" or stop the running owner.
var ErrOwnerRunning = errors.New("daemon owner already running")

// ErrFrameTooLarge is returned when the length prefix of an incoming frame
// exceeds maxFrameSize. The buffer is never allocated.
var ErrFrameTooLarge = errors.New("ipc: frame too large")

// ---- Frame types -------------------------------------------------------------

// Request is the opening frame sent by the CLI on each socket connection.
// Both Kind and SocketSchema are mandatory. Unknown CBOR fields are rejected
// by the server to prevent drift.
type Request struct {
	SocketSchema int               `cbor:"socket_schema"`
	Kind         string            `cbor:"kind"`
	Method       string            `cbor:"method,omitempty"`
	Server       string            `cbor:"server,omitempty"`
	Target       string            `cbor:"target,omitempty"`
	Meta         map[string]string `cbor:"meta,omitempty"`
	Args         cbor.RawMessage   `cbor:"args,omitempty"`
}

// Response is the frame sent by the daemon in reply to a Request. A Status of
// 0 means success; non-zero values map to the global exit-code conventions.
// Body carries the raw JSON bytes of an RPC result (e.g. the status snapshot).
// It is encoded as a CBOR byte string so the receiver gets back the same JSON
// bytes without any re-encoding.
type Response struct {
	SocketSchema int    `cbor:"socket_schema"`
	Status       uint   `cbor:"status"`
	Msg          string `cbor:"msg,omitempty"`
	Body         []byte `cbor:"body,omitempty"`
}

// ---- Low-level frame I/O -----------------------------------------------------

// writeFrame writes a single IPC frame: version(1) | length-BE(4) | payload.
// A 4-byte length field (instead of the wire proto's 2-byte field) accommodates
// the larger status snapshots that can appear in RPC responses.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	buf := make([]byte, 5+len(payload))
	buf[0] = ipcFrameVersion
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

// readFrame reads one IPC frame. The length prefix is validated before
// allocating the payload buffer so an oversize frame is rejected cheaply.
// An opening-read deadline should be set on the net.Conn before calling
// readFrame for the first request; that deadline is the caller's responsibility.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != ipcFrameVersion {
		return nil, fmt.Errorf("ipc: unexpected frame version 0x%02x (expected 0x%02x)", hdr[0], ipcFrameVersion)
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if int(n) > maxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// writeRequest encodes and sends req.
func writeRequest(w io.Writer, req Request) error {
	payload, err := encMode.Marshal(req)
	if err != nil {
		return fmt.Errorf("ipc: marshal request: %w", err)
	}
	return writeFrame(w, payload)
}

// readRequest decodes a Request from the next frame.
// Unknown CBOR fields cause a decode error (strict mode), matching the
// project-wide strict-decode discipline for IPC frames.
func readRequest(r io.Reader) (Request, error) {
	payload, err := readFrame(r)
	if err != nil {
		return Request{}, err
	}
	dm, dmErr := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()
	if dmErr != nil {
		return Request{}, fmt.Errorf("ipc: build strict decode mode: %w", dmErr)
	}
	var req Request
	if err := dm.Unmarshal(payload, &req); err != nil {
		return Request{}, fmt.Errorf("ipc: decode request: %w", err)
	}
	return req, nil
}

// writeResponse encodes and sends resp.
func writeResponse(w io.Writer, resp Response) error {
	payload, err := encMode.Marshal(resp)
	if err != nil {
		return fmt.Errorf("ipc: marshal response: %w", err)
	}
	return writeFrame(w, payload)
}

// readResponse decodes a Response from the next frame.
func readResponse(r io.Reader) (Response, error) {
	payload, err := readFrame(r)
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := cbor.Unmarshal(payload, &resp); err != nil {
		return Response{}, fmt.Errorf("ipc: decode response: %w", err)
	}
	return resp, nil
}

// schemaMismatchResponse returns a Response that signals a schema mismatch.
// It always carries SocketSchema=SocketSchema so the peer can identify the
// daemon's schema even when the requested schema was wrong.
func schemaMismatchResponse(clientSchema int) Response {
	return Response{
		SocketSchema: SocketSchema,
		Status:       1,
		Msg:          fmt.Sprintf("socket schema mismatch: client sent %d, daemon speaks %d; restart the daemon", clientSchema, SocketSchema),
	}
}

// errorResponse returns a Response carrying a non-zero status and message.
func errorResponse(status uint, msg string) Response {
	return Response{
		SocketSchema: SocketSchema,
		Status:       status,
		Msg:          msg,
	}
}

// okResponse returns a successful Response with an optional body. body should
// be the raw JSON bytes of the RPC result; they are carried as a CBOR byte
// string so the receiver gets back the exact same bytes.
func okResponse(body []byte) Response {
	return Response{
		SocketSchema: SocketSchema,
		Status:       0,
		Body:         body,
	}
}

// isNetRefused reports whether err is a connection-refused condition (no
// listener at the socket path). Used by the Client to distinguish
// ErrDaemonAbsent from other dial failures.
//
// errors.Is unwraps *net.OpError → *os.SyscallError → syscall.Errno on both
// Linux and macOS, so we match the errno directly rather than string-comparing
// the error message. String comparison breaks on darwin where the wrapped error
// message is "connect: connection refused" (with a prefix) rather than the bare
// "connection refused" the old code expected.
func isNetRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
