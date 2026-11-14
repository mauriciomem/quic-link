package pairing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// FrameVersion prefixes every pairing frame. It is deliberately distinct
	// from proto.ProtoVersion so pairing and tunnel frames never misparse as
	// each other.
	FrameVersion = 0x50
	// MaxFramePayload is the largest pairing frame payload in bytes.
	MaxFramePayload = 4096
)

// Frame errors.
var (
	ErrFrameVersion  = errors.New("pairing: unexpected frame version")
	ErrFrameTooLarge = errors.New("pairing: frame too large")
)

// WriteFrame writes version(1) | length-BE(2) | payload in a single write.
// Nothing is written when payload exceeds MaxFramePayload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	buf := make([]byte, 3+len(payload))
	buf[0] = FrameVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one pairing frame. A wrong version is refused after reading
// only the version byte; an oversize declared length is refused before any
// payload is read.
func ReadFrame(r io.Reader) ([]byte, error) {
	var v [1]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return nil, err
	}
	if v[0] != FrameVersion {
		return nil, fmt.Errorf("%w: 0x%02x", ErrFrameVersion, v[0])
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > MaxFramePayload {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
