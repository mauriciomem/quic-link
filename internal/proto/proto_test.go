package proto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestVectorsRoundTrip covers canonical encode plus decode round-trips, byte-exact.
func TestVectorsRoundTrip(t *testing.T) {
	v1 := mustHex(t, "01 00 15 a2 64 6b 69 6e 64 63 74 63 70 66 74 61 72 67 65 74 63 73 73 68")
	v2 := mustHex(t, "01 00 0e a2 66 73 74 61 74 75 73 00 63 6d 73 67 60")

	t.Run("V1 header encode", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteHeader(&buf, Header{Kind: KindTCP, Target: "ssh"}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if !bytes.Equal(buf.Bytes(), v1) {
			t.Fatalf("V1 encode mismatch:\n got %x\nwant %x", buf.Bytes(), v1)
		}
	})
	t.Run("V1 header decode", func(t *testing.T) {
		h, err := ReadHeader(bytes.NewReader(v1))
		if err != nil {
			t.Fatalf("ReadHeader: %v", err)
		}
		if h.Kind != KindTCP || h.Target != "ssh" {
			t.Fatalf("V1 decode mismatch: got %+v", h)
		}
	})
	t.Run("V2 response encode", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteResponse(&buf, Response{Status: StatusOK, Msg: ""}); err != nil {
			t.Fatalf("WriteResponse: %v", err)
		}
		if !bytes.Equal(buf.Bytes(), v2) {
			t.Fatalf("V2 encode mismatch:\n got %x\nwant %x", buf.Bytes(), v2)
		}
	})
	t.Run("V2 response decode", func(t *testing.T) {
		r, err := ReadResponse(bytes.NewReader(v2))
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		if r.Status != StatusOK || r.Msg != "" {
			t.Fatalf("V2 decode mismatch: got %+v", r)
		}
	})
}

// TestVectorsReject covers version, size, and bad-target rejections.
func TestVectorsReject(t *testing.T) {
	frameCases := []struct {
		name    string
		frame   string
		wantErr error
	}{
		{"V3 unsupported version", "02 00 01 ff", ErrUnsupportedVersion},
		{"V4 frame too large", "01 10 01 00", ErrFrameTooLarge},
	}
	for _, tc := range frameCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(mustHex(t, tc.frame)))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadFrame err = %v, want %v", err, tc.wantErr)
			}
		})
	}

	t.Run("V5 target with colon rejected", func(t *testing.T) {
		payload, err := Header{Kind: KindTCP, Target: "127.0.0.1:9000"}.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if _, err := ParseHeader(payload); !errors.Is(err, ErrBadHeader) {
			t.Fatalf("ParseHeader err = %v, want ErrBadHeader", err)
		}
	})
}
