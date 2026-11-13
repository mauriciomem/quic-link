/**
 * @spec-handoff
 * @interface WriteFrame(w io.Writer, payload []byte) error; ReadFrame(r io.Reader) ([]byte, error); FrameVersion = 0x50; MaxFramePayload = 4096
 * @behavior
 *   - Frame = FrameVersion byte, u16 big-endian length, payload (proto shape, own version)
 *   - FrameVersion != proto.ProtoVersion; internal/proto is untouched (ProtoVersion stays 0x01)
 *   - Wrong version -> ErrFrameVersion; declared/actual payload > 4096 -> ErrFrameTooLarge; neither consumes the payload
 * @edge-cases
 *   - proto frame read by pairing.ReadFrame -> ErrFrameVersion; pairing frame read by proto.ReadFrame -> proto.ErrUnsupportedVersion
 *   - Truncated header or payload -> io error, never a payload
 * @see RFC 001 pairing-wire-protocol.md §1 (OD-8); plan 18 D3, K22
 */

package pairing_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/mauriciomem/quic-link/internal/pairing"
	"github.com/mauriciomem/quic-link/internal/proto"
)

func TestPairingFrame_OwnVersion(t *testing.T) {
	if pairing.FrameVersion != 0x50 {
		t.Fatalf("FrameVersion = 0x%02x, want 0x50", pairing.FrameVersion)
	}
	if proto.ProtoVersion != 0x01 {
		t.Fatalf("proto.ProtoVersion changed: 0x%02x", proto.ProtoVersion)
	}
	if byte(pairing.FrameVersion) == byte(proto.ProtoVersion) {
		t.Fatal("pairing frame version collides with proto.ProtoVersion")
	}
	if pairing.MaxFramePayload != 4096 {
		t.Fatalf("MaxFramePayload = %d", pairing.MaxFramePayload)
	}
	for _, payload := range [][]byte{{}, []byte("abc"), bytes.Repeat([]byte{7}, pairing.MaxFramePayload)} {
		var buf bytes.Buffer
		if err := pairing.WriteFrame(&buf, payload); err != nil {
			t.Fatalf("WriteFrame(%d): %v", len(payload), err)
		}
		raw := buf.Bytes()
		if len(raw) != 3+len(payload) || raw[0] != 0x50 || int(raw[1])<<8|int(raw[2]) != len(payload) || !bytes.Equal(raw[3:], payload) {
			t.Fatalf("frame layout wrong: % x", raw[:min(len(raw), 8)])
		}
		got, err := pairing.ReadFrame(bytes.NewReader(raw))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("ReadFrame round trip: %v", err)
		}
	}
}

func TestPairingFrame_Refusals(t *testing.T) {
	t.Run("proto_frame_into_pairing", func(t *testing.T) {
		var buf bytes.Buffer
		if err := proto.WriteFrame(&buf, []byte("abc")); err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(buf.Bytes())
		if _, err := pairing.ReadFrame(r); !errors.Is(err, pairing.ErrFrameVersion) {
			t.Fatalf("err = %v, want ErrFrameVersion", err)
		}
		if r.Len() != len(buf.Bytes())-1 {
			t.Fatalf("consumed past version byte: %d left", r.Len())
		}
	})
	t.Run("pairing_frame_into_proto", func(t *testing.T) {
		var buf bytes.Buffer
		if err := pairing.WriteFrame(&buf, []byte("abc")); err != nil {
			t.Fatal(err)
		}
		if _, err := proto.ReadFrame(&buf); !errors.Is(err, proto.ErrUnsupportedVersion) {
			t.Fatalf("err = %v, want proto.ErrUnsupportedVersion", err)
		}
	})
	t.Run("other_versions", func(t *testing.T) {
		for _, v := range []byte{0x00, 0x01, 0x02, 0x4f, 0x51, 0xff} {
			if _, err := pairing.ReadFrame(bytes.NewReader([]byte{v, 0, 0})); !errors.Is(err, pairing.ErrFrameVersion) {
				t.Errorf("version 0x%02x: err = %v", v, err)
			}
		}
	})
	t.Run("oversize_write", func(t *testing.T) {
		var buf bytes.Buffer
		if err := pairing.WriteFrame(&buf, make([]byte, pairing.MaxFramePayload+1)); !errors.Is(err, pairing.ErrFrameTooLarge) {
			t.Fatalf("err = %v", err)
		}
		if buf.Len() != 0 {
			t.Fatalf("wrote %d bytes on refusal", buf.Len())
		}
	})
	t.Run("oversize_declared", func(t *testing.T) {
		raw := append([]byte{0x50, 0x10, 0x01}, make([]byte, 4097)...)
		r := bytes.NewReader(raw)
		if _, err := pairing.ReadFrame(r); !errors.Is(err, pairing.ErrFrameTooLarge) {
			t.Fatalf("err = %v", err)
		}
		if r.Len() != 4097 {
			t.Fatalf("payload consumed: %d left", r.Len())
		}
	})
	t.Run("truncated", func(t *testing.T) {
		for name, raw := range map[string][]byte{
			"empty": {}, "version_only": {0x50}, "half_length": {0x50, 0x00},
			"short_payload": {0x50, 0x00, 0x05, 'a', 'b'},
		} {
			got, err := pairing.ReadFrame(bytes.NewReader(raw))
			if err == nil || got != nil {
				t.Errorf("%s: got %v, %v", name, got, err)
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("%s: err = %v, want io EOF class", name, err)
			}
		}
	})
}
