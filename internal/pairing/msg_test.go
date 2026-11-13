/**
 * @spec-handoff
 * @interface PairRequest{Method,Label(omitempty),Proof}.Marshal(); PairResponse{Status,Msg}.Marshal(); ParsePairRequest([]byte) (PairRequest, error); ParsePairResponse([]byte) (PairResponse, error); StatusForParseError(error) Status; ExitCodeForPairing(Status) int
 * @behavior
 *   - Encoding uses cbor.CoreDetEncOptions(): keys sorted bytewise (request label,proof,method; response msg,status)
 *   - Status 0..6 = ok,bad_proof,window_closed,rate_limited,bad_header,unsupported_method,conflict
 *   - ParsePairRequest strict: CBOR error/unknown key/dup key/indef length/tag/trailing bytes/wrong type,
 *     empty method, proof len != 32, label > 64 bytes or byte outside 0x20..0x7e or '#' -> ErrBadHeader (status 4)
 *   - Non-empty unknown method -> ErrUnsupportedMethod (status 5), checked before proof length
 *   - ExitCodeForPairing: 0->0; 1,2,3,6->6; 4,5->1
 * @edge-cases
 *   - ParsePairResponse with unknown status (7) -> error
 * @see RFC 001 pairing-wire-protocol.md §5, OD-26; plan 18 D3a
 */

package pairing_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mauriciomem/quic-link/internal/pairing"
)

// Byte vectors below are regenerated at wire freeze (OD-26).

func h(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

var proof32 = bytes.Repeat([]byte{0x11}, 32)

const (
	hexProof32   = "5820" + "1111111111111111111111111111111111111111111111111111111111111111"
	hexKeyLabel  = "656c6162656c"
	hexKeyProof  = "6570726f6f66"
	hexKeyMethod = "666d6574686f64"
	hexMethodV1  = "6d746f6b656e2d686d61632d7631"
)

func TestPairRequest_Vectors(t *testing.T) {
	cases := []struct {
		name string
		req  pairing.PairRequest
		want string
	}{
		{"with_label", pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: "laptop", Proof: proof32},
			"a3" + hexKeyLabel + "666c6170746f70" + hexKeyProof + hexProof32 + hexKeyMethod + hexMethodV1},
		{"label_omitted", pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Proof: proof32},
			"a2" + hexKeyProof + hexProof32 + hexKeyMethod + hexMethodV1},
	}
	if pairing.MethodTokenHMACv1 != "token-hmac-v1" {
		t.Fatalf("MethodTokenHMACv1 = %q", pairing.MethodTokenHMACv1)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.req.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if want := h(t, c.want); !bytes.Equal(got, want) {
				t.Fatalf("vector mismatch\n got %x\nwant %x", got, want)
			}
			back, err := pairing.ParsePairRequest(got)
			if err != nil {
				t.Fatalf("ParsePairRequest(vector): %v", err)
			}
			if back.Method != c.req.Method || back.Label != c.req.Label || !bytes.Equal(back.Proof, c.req.Proof) {
				t.Fatalf("round trip: got %+v want %+v", back, c.req)
			}
		})
	}
}

func TestPairResponse_VectorsEveryStatus(t *testing.T) {
	names := []string{"ok", "bad_proof", "window_closed", "rate_limited", "bad_header", "unsupported_method", "conflict"}
	consts := []pairing.Status{pairing.StatusOK, pairing.StatusBadProof, pairing.StatusWindowClosed,
		pairing.StatusRateLimited, pairing.StatusBadHeader, pairing.StatusUnsupportedMethod, pairing.StatusConflict}
	for i, s := range consts {
		if uint(s) != uint(i) {
			t.Fatalf("status %s = %d, want %d", names[i], s, i)
		}
		if s.String() != names[i] {
			t.Errorf("Status(%d).String() = %q, want %q", i, s.String(), names[i])
		}
		// {"msg": "", "status": i}
		want := h(t, "a2"+"636d7367"+"60"+"66737461747573"+hex.EncodeToString([]byte{byte(i)}))
		got, err := pairing.PairResponse{Status: s}.Marshal()
		if err != nil {
			t.Fatalf("Marshal status %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("status %d vector\n got %x\nwant %x", i, got, want)
		}
	}
	got, err := pairing.PairResponse{Status: pairing.StatusConflict, Msg: "hi"}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if want := h(t, "a2 636d7367 626869 66737461747573 06"); !bytes.Equal(got, want) {
		t.Fatalf("msg vector\n got %x\nwant %x", got, want)
	}
}

func TestParsePairRequest_Rules(t *testing.T) {
	valid := pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Proof: proof32}
	enc := func(m map[string]any) []byte {
		b, err := cbor.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	withLabel := func(l string) []byte {
		r := valid
		r.Label = l
		b, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	validBytes, err := valid.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body := hexKeyProof + hexProof32 + hexKeyMethod + hexMethodV1

	bad := []struct {
		name    string
		payload []byte
		want    error
	}{
		{"empty_payload", nil, pairing.ErrBadHeader},
		{"garbage", []byte{0xff, 0x00}, pairing.ErrBadHeader},
		{"not_a_map", h(t, "83010203"), pairing.ErrBadHeader},
		{"unknown_key", enc(map[string]any{"method": pairing.MethodTokenHMACv1, "proof": proof32, "x": 1}), pairing.ErrBadHeader},
		{"duplicate_key", h(t, "a3"+hexKeyProof+hexProof32+hexKeyMethod+hexMethodV1+hexKeyMethod+hexMethodV1), pairing.ErrBadHeader},
		{"indefinite_map", h(t, "bf"+body+"ff"), pairing.ErrBadHeader},
		{"indefinite_proof_bytes", h(t, "a2"+hexKeyProof+"5f5810"+strings.Repeat("11", 16)+"5810"+strings.Repeat("11", 16)+"ff"+hexKeyMethod+hexMethodV1), pairing.ErrBadHeader},
		{"tagged_map", h(t, "d9d9f7a2"+body), pairing.ErrBadHeader},
		{"tagged_proof", h(t, "a2"+hexKeyProof+"d818"+hexProof32+hexKeyMethod+hexMethodV1), pairing.ErrBadHeader},
		{"trailing_bytes", append(append([]byte{}, validBytes...), 0x00), pairing.ErrBadHeader},
		{"proof_wrong_type", enc(map[string]any{"method": pairing.MethodTokenHMACv1, "proof": "abc"}), pairing.ErrBadHeader},
		{"method_wrong_type", enc(map[string]any{"method": 1, "proof": proof32}), pairing.ErrBadHeader},
		{"label_wrong_type", enc(map[string]any{"method": pairing.MethodTokenHMACv1, "proof": proof32, "label": 5}), pairing.ErrBadHeader},
		{"method_missing", enc(map[string]any{"proof": proof32}), pairing.ErrBadHeader},
		{"method_empty", enc(map[string]any{"method": "", "proof": proof32}), pairing.ErrBadHeader},
		{"proof_missing", enc(map[string]any{"method": pairing.MethodTokenHMACv1}), pairing.ErrBadHeader},
		{"proof_31", enc(map[string]any{"method": pairing.MethodTokenHMACv1, "proof": proof32[:31]}), pairing.ErrBadHeader},
		{"proof_33", enc(map[string]any{"method": pairing.MethodTokenHMACv1, "proof": append(append([]byte{}, proof32...), 1)}), pairing.ErrBadHeader},
		{"label_65_bytes", withLabel(strings.Repeat("a", 65)), pairing.ErrBadHeader},
		{"label_newline", withLabel("lap\ntop"), pairing.ErrBadHeader},
		{"label_hash", withLabel("lap#top"), pairing.ErrBadHeader},
		{"label_control", withLabel("lap\x01top"), pairing.ErrBadHeader},
		{"label_del", withLabel("lap\x7ftop"), pairing.ErrBadHeader},
		{"label_non_ascii", withLabel("lapté"), pairing.ErrBadHeader},
		{"unknown_method", enc(map[string]any{"method": "token-hmac-v2", "proof": proof32}), pairing.ErrUnsupportedMethod},
		{"unknown_method_bad_proof", enc(map[string]any{"method": "token-hmac-v2", "proof": proof32[:3]}), pairing.ErrUnsupportedMethod},
		{"unknown_method_unknown_key", enc(map[string]any{"method": "token-hmac-v2", "proof": proof32, "x": 1}), pairing.ErrBadHeader},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := pairing.ParsePairRequest(c.payload)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			other := pairing.ErrUnsupportedMethod
			wantStatus := pairing.StatusBadHeader
			if c.want == pairing.ErrUnsupportedMethod {
				other, wantStatus = pairing.ErrBadHeader, pairing.StatusUnsupportedMethod
			}
			if errors.Is(err, other) {
				t.Fatalf("err %v matches both sentinels", err)
			}
			if s := pairing.StatusForParseError(err); s != wantStatus {
				t.Fatalf("StatusForParseError = %v, want %v", s, wantStatus)
			}
		})
	}

	good := []string{"", "a", strings.Repeat("a", 64), " ~printable ASCII!"}
	for _, l := range good {
		r, err := pairing.ParsePairRequest(withLabel(l))
		if err != nil {
			t.Errorf("label %q refused: %v", l, err)
			continue
		}
		if r.Label != l {
			t.Errorf("label = %q, want %q", r.Label, l)
		}
	}
	if pairing.MaxLabelLen != 64 {
		t.Errorf("MaxLabelLen = %d, want 64", pairing.MaxLabelLen)
	}
}

func TestParsePairResponse(t *testing.T) {
	for s := pairing.StatusOK; s <= pairing.StatusConflict; s++ {
		b, err := pairing.PairResponse{Status: s, Msg: "m"}.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := pairing.ParsePairResponse(b)
		if err != nil {
			t.Fatalf("status %d: %v", s, err)
		}
		if got.Status != s || got.Msg != "m" {
			t.Fatalf("round trip = %+v", got)
		}
	}
	for name, p := range map[string][]byte{
		"unknown_status_7": h(t, "a2 636d7367 60 66737461747573 07"),
		"unknown_key":      h(t, "a3 636d7367 60 66737461747573 00 6178 01"),
		"duplicate_key":    h(t, "a3 636d7367 60 66737461747573 00 66737461747573 01"),
		"indefinite_map":   h(t, "bf 636d7367 60 66737461747573 00 ff"),
		"tagged":           h(t, "c1 a2 636d7367 60 66737461747573 00"),
		"trailing":         h(t, "a2 636d7367 60 66737461747573 00 00"),
		"status_wrong":     h(t, "a2 636d7367 60 66737461747573 6130"),
		"empty":            nil,
	} {
		if _, err := pairing.ParsePairResponse(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExitCodeForPairing(t *testing.T) {
	want := map[pairing.Status]int{
		pairing.StatusOK: 0, pairing.StatusBadProof: 6, pairing.StatusWindowClosed: 6,
		pairing.StatusRateLimited: 6, pairing.StatusConflict: 6,
		pairing.StatusBadHeader: 1, pairing.StatusUnsupportedMethod: 1,
	}
	for s, code := range want {
		if got := pairing.ExitCodeForPairing(s); got != code {
			t.Errorf("ExitCodeForPairing(%v) = %d, want %d", s, got, code)
		}
	}
}

func TestPairingCBOR_Deterministic(t *testing.T) {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	// Map-valued field: Go map iteration is random, encoding must not be.
	type withMap struct {
		Z string            `cbor:"zz"`
		M map[string]string `cbor:"m"`
		A uint              `cbor:"aaa"`
	}
	v := withMap{Z: "z", A: 7, M: map[string]string{}}
	for i := 0; i < 32; i++ {
		v.M[string(rune('a'+i%26))+strings.Repeat("k", i)] = "v"
	}
	first, err := em.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		b, _ := em.Marshal(v)
		if !bytes.Equal(b, first) {
			t.Fatalf("run %d differs", i)
		}
	}

	req := pairing.PairRequest{Method: pairing.MethodTokenHMACv1, Label: "box-1", Proof: proof32}
	resp := pairing.PairResponse{Status: pairing.StatusRateLimited, Msg: "slow down"}
	for name, pair := range map[string]struct {
		marshal func() ([]byte, error)
		value   any
		reparse func([]byte) ([]byte, error)
	}{
		"request": {req.Marshal, req, func(b []byte) ([]byte, error) {
			r, err := pairing.ParsePairRequest(b)
			if err != nil {
				return nil, err
			}
			return r.Marshal()
		}},
		"response": {resp.Marshal, resp, func(b []byte) ([]byte, error) {
			r, err := pairing.ParsePairResponse(b)
			if err != nil {
				return nil, err
			}
			return r.Marshal()
		}},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := pair.marshal()
			if err != nil {
				t.Fatal(err)
			}
			core, err := em.Marshal(pair.value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, core) {
				t.Fatalf("package encoding is not CoreDetEncOptions\n got %x\nwant %x", b, core)
			}
			again, err := pair.reparse(b)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, b) {
				t.Fatalf("encode->decode->re-encode differs\n got %x\nwant %x", again, b)
			}
			for i := 0; i < 100; i++ {
				x, _ := pair.marshal()
				if !bytes.Equal(x, b) {
					t.Fatalf("run %d differs", i)
				}
			}
		})
	}
}

func FuzzParsePairRequest(f *testing.F) {
	for _, r := range []pairing.PairRequest{
		{Method: pairing.MethodTokenHMACv1, Proof: proof32},
		{Method: pairing.MethodTokenHMACv1, Label: "laptop", Proof: proof32},
		{Method: "other", Proof: proof32},
	} {
		b, _ := r.Marshal()
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := pairing.ParsePairRequest(data)
		if err != nil {
			if !errors.Is(err, pairing.ErrBadHeader) && !errors.Is(err, pairing.ErrUnsupportedMethod) {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		if r.Method != pairing.MethodTokenHMACv1 || len(r.Proof) != 32 || len(r.Label) > pairing.MaxLabelLen {
			t.Fatalf("accepted invalid request %+v", r)
		}
		for i := 0; i < len(r.Label); i++ {
			if c := r.Label[i]; c < 0x20 || c > 0x7e || c == '#' {
				t.Fatalf("accepted label byte 0x%02x", c)
			}
		}
		b, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, data) {
			t.Fatalf("accepted non-canonical encoding %x (canonical %x)", data, b)
		}
	})
}
