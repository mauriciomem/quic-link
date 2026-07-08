// Package proto implements the quic-link wire protocol v1: length-
// prefixed frames carrying CBOR payloads. A stream begins with exactly one
// header frame (initiator -> acceptor) and one response frame (acceptor ->
// initiator) before any payload flows. ProtoVersion is the frame
// version byte and moves with any change to bytes or semantics.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Protocol constants.
const (
	// ProtoVersion is the frame version byte and the control
	// stream meta.proto value; they move together.
	ProtoVersion = 0x01
	// MaxFramePayload is the maximum CBOR payload length in a single frame.
	MaxFramePayload = 4096
	// ResponseDeadline bounds the wait from header write to response receipt
	// on the initiator.
	ResponseDeadline = 10 * time.Second
	// StreamResetCode is the QUIC stream reset application code.
	StreamResetCode = 0x10
)

// Stream kinds.
const (
	KindTCP     = "tcp"
	KindHTTP    = "http"
	KindControl = "control"
)

// Status is a response status code.
type Status uint

const (
	StatusOK                 Status = 0 // proceed to payload
	StatusUnknownTarget      Status = 1 // no route/vhost entry
	StatusUnauthorized       Status = 2 // authz denied
	StatusDialFailed         Status = 3 // route exists, dial errored
	StatusDraining           Status = 4 // agent shutting down
	StatusBadHeader          Status = 5 // malformed/missing fields
	StatusUnsupportedVersion Status = 6 // frame ver or control proto unacceptable
)

// String returns the status name.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusUnknownTarget:
		return "unknown_target"
	case StatusUnauthorized:
		return "unauthorized"
	case StatusDialFailed:
		return "dial_failed"
	case StatusDraining:
		return "draining"
	case StatusBadHeader:
		return "bad_header"
	case StatusUnsupportedVersion:
		return "unsupported_version"
	default:
		return fmt.Sprintf("status(%d)", uint(s))
	}
}

// Frame/parse errors. Callers map these to protocol behavior:
// ErrUnsupportedVersion -> status 6 (acceptor) or stream reset
// (response side); ErrFrameTooLarge -> stream reset, no response;
// ErrBadHeader -> status 5.
var (
	ErrUnsupportedVersion = errors.New("proto: unsupported version")
	ErrFrameTooLarge      = errors.New("proto: frame payload exceeds maximum")
	ErrBadHeader          = errors.New("proto: malformed header")
)

// encMode pins definition-order (SortNone) CBOR encoding so the test vectors
// round-trip byte-exactly. Canonical/length-first sorting would
// reorder keys and MUST NOT be used here.
var encMode cbor.EncMode

func init() {
	em, err := cbor.EncOptions{Sort: cbor.SortNone}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("proto: build CBOR encode mode: %v", err))
	}
	encMode = em
}

// Header is the request frame payload. Field order matches the
// canonical vectors (kind, target, ...); do not reorder.
type Header struct {
	Kind   string            `cbor:"kind"`
	Target string            `cbor:"target,omitempty"`
	Host   string            `cbor:"host,omitempty"`
	Port   uint              `cbor:"port,omitempty"`
	Meta   map[string]string `cbor:"meta,omitempty"`
}

// Response is the reply frame payload. Field order (status,
// msg) is significant for the vectors; msg is always encoded (may be "").
type Response struct {
	Status Status `cbor:"status"`
	Msg    string `cbor:"msg"`
}

// WriteFrame writes payload as one length-prefixed frame.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	buf := make([]byte, 3+len(payload))
	buf[0] = ProtoVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame and returns its payload. It
// returns ErrUnsupportedVersion if the version byte is not ProtoVersion and
// ErrFrameTooLarge if the declared length exceeds MaxFramePayload; neither
// consumes the payload.
func ReadFrame(r io.Reader) ([]byte, error) {
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, err
	}
	if ver[0] != ProtoVersion {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, ver[0])
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if int(n) > MaxFramePayload {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// Marshal encodes the header payload in definition order.
func (h Header) Marshal() ([]byte, error) { return encMode.Marshal(h) }

// Marshal encodes the response payload in definition order.
func (r Response) Marshal() ([]byte, error) { return encMode.Marshal(r) }

// ParseHeader decodes and validates a header payload. Unknown
// CBOR keys are ignored. Validation failures return ErrBadHeader.
func ParseHeader(payload []byte) (Header, error) {
	var h Header
	if err := cbor.Unmarshal(payload, &h); err != nil {
		return Header{}, fmt.Errorf("%w: %v", ErrBadHeader, err)
	}
	switch h.Kind {
	case KindTCP:
		if h.Target == "" {
			return Header{}, fmt.Errorf("%w: tcp header missing target", ErrBadHeader)
		}
		// A logical name, never an ip:port. Reject ':' and '/'.
		if strings.ContainsAny(h.Target, ":/") {
			return Header{}, fmt.Errorf("%w: target %q must be a logical name, not an address", ErrBadHeader, h.Target)
		}
	case KindHTTP:
		if h.Host == "" {
			return Header{}, fmt.Errorf("%w: http header missing host", ErrBadHeader)
		}
	case KindControl:
		// no additional required fields
	default:
		return Header{}, fmt.Errorf("%w: unknown kind %q", ErrBadHeader, h.Kind)
	}
	return h, nil
}

// ParseResponse decodes a response payload.
func ParseResponse(payload []byte) (Response, error) {
	var resp Response
	if err := cbor.Unmarshal(payload, &resp); err != nil {
		return Response{}, fmt.Errorf("proto: parse response: %w", err)
	}
	return resp, nil
}

// WriteHeader marshals and writes a header frame.
func WriteHeader(w io.Writer, h Header) error {
	p, err := h.Marshal()
	if err != nil {
		return fmt.Errorf("proto: marshal header: %w", err)
	}
	return WriteFrame(w, p)
}

// ReadHeader reads and validates a header frame.
func ReadHeader(r io.Reader) (Header, error) {
	p, err := ReadFrame(r)
	if err != nil {
		return Header{}, err
	}
	return ParseHeader(p)
}

// WriteResponse marshals and writes a response frame.
func WriteResponse(w io.Writer, resp Response) error {
	p, err := resp.Marshal()
	if err != nil {
		return fmt.Errorf("proto: marshal response: %w", err)
	}
	return WriteFrame(w, p)
}

// ReadResponse reads a response frame.
func ReadResponse(r io.Reader) (Response, error) {
	p, err := ReadFrame(r)
	if err != nil {
		return Response{}, err
	}
	return ParseResponse(p)
}
