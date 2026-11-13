/**
 * @spec-handoff
 * @interface NewBlob(listenerPinB64 string) (Blob, error); (Blob) Encode() string; ParseBlob(s string) (Blob, error); (Blob) PinB64() string
 * @behavior
 *   - Encode = "QLJ1-" + base64.RawURLEncoding(0x01 || Secret[16] || ListenerPin[32]); always BlobLen (71) chars
 *   - ParseBlob(Encode(b)) == b; PinB64 is base64.StdEncoding of ListenerPin
 *   - NewBlob fills Secret from crypto/rand; pin must be std-b64, 32 bytes, canonical (no normalization)
 * @edge-cases
 *   - Order: prefix -> decode -> length != 49 -> version != 0x01 -> re-encode != input
 *   - Errors (errors.Is-distinct): ErrBlobPrefix, ErrBlobDecode, ErrBlobLength, ErrBlobVersion, ErrBlobNonCanonical
 *   - 15 non-canonical spellings of the last char refused; ErrBlobNonCanonical text says the "last character" looks mistyped
 *   - No trimming; every ParseBlob error is exactly one sentinel (no blob material in error text)
 *   - Redaction: fmt (%v %+v %#v %s), slog (Text/JSON via LogValue) and json.Marshal of a Blob show a "redacted"
 *     marker and never the secret (raw/hex/base64) nor the encoded blob body
 * @see ../identity/pin.go (ParsePinStrict)
 */

package pairing_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/pairing"
)

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func fixedBlob() pairing.Blob {
	var b pairing.Blob
	for i := range b.Secret {
		b.Secret[i] = byte(0xA0 + i)
	}
	b.ListenerPin = sha256.Sum256([]byte("listener spki"))
	return b
}

func TestBlob_RoundTrip(t *testing.T) {
	b := fixedBlob()
	s := b.Encode()
	if len(s) != pairing.BlobLen || pairing.BlobLen != 71 {
		t.Fatalf("len = %d, BlobLen = %d, want 71", len(s), pairing.BlobLen)
	}
	if !strings.HasPrefix(s, pairing.BlobPrefix) || pairing.BlobPrefix != "QLJ1-" {
		t.Fatalf("prefix: %q", s)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[5:])
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{0x01}, b.Secret[:]...), b.ListenerPin[:]...)
	if !bytes.Equal(raw, want) {
		t.Fatalf("payload layout mismatch:\n got %x\nwant %x", raw, want)
	}
	got, err := pairing.ParseBlob(s)
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}
	if got != b {
		t.Fatalf("round trip mismatch")
	}
	if got.PinB64() != base64.StdEncoding.EncodeToString(b.ListenerPin[:]) {
		t.Fatalf("PinB64 = %q", got.PinB64())
	}
}

func TestParseBlob_Defects(t *testing.T) {
	b := fixedBlob()
	good := b.Encode()
	body := good[5:]
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	badVer := append([]byte{0x02}, raw[1:]...)
	secretB64 := base64.RawURLEncoding.EncodeToString(b.Secret[:])

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"no prefix", body, pairing.ErrBlobPrefix},
		{"lowercase prefix", "qlj1-" + body, pairing.ErrBlobPrefix},
		{"leading space", " " + good, pairing.ErrBlobPrefix},
		{"empty", "", pairing.ErrBlobPrefix},
		{"std alphabet char", "QLJ1-" + strings.Replace(body[:10], body[:1], "+", 1) + body[10:], pairing.ErrBlobDecode},
		{"padding", good + "==", pairing.ErrBlobDecode},
		{"trailing newline", good + "\n", pairing.ErrBlobDecode},
		{"short", "QLJ1-" + base64.RawURLEncoding.EncodeToString(raw[:48]), pairing.ErrBlobLength},
		{"long", "QLJ1-" + base64.RawURLEncoding.EncodeToString(append(raw, 0)), pairing.ErrBlobLength},
		{"bad version", "QLJ1-" + base64.RawURLEncoding.EncodeToString(badVer), pairing.ErrBlobVersion},
	}
	all := []error{pairing.ErrBlobPrefix, pairing.ErrBlobDecode, pairing.ErrBlobLength, pairing.ErrBlobVersion, pairing.ErrBlobNonCanonical}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pairing.ParseBlob(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			for _, other := range all {
				if other != tc.want && errors.Is(err, other) {
					t.Fatalf("err %v also matches %v", err, other)
				}
			}
			if strings.Contains(err.Error(), secretB64) || strings.Contains(err.Error(), body) {
				t.Fatalf("error leaks blob material: %v", err)
			}
		})
	}
}

func TestParseBlob_RefusesNonCanonicalTrailingBits(t *testing.T) {
	b := fixedBlob()
	good := b.Encode()
	last := strings.IndexByte(b64url, good[len(good)-1])
	if last&0x0f != 0 {
		t.Fatalf("canonical last char %q has non-zero unused bits", good[len(good)-1])
	}
	if _, err := pairing.ParseBlob(good); err != nil {
		t.Fatalf("canonical spelling refused: %v", err)
	}
	refused := 0
	for low := 1; low < 16; low++ {
		c := b64url[last|low]
		s := good[:len(good)-1] + string(c)
		_, err := pairing.ParseBlob(s)
		if !errors.Is(err, pairing.ErrBlobNonCanonical) {
			t.Errorf("last char %q: err = %v, want ErrBlobNonCanonical", c, err)
			continue
		}
		refused++
	}
	if refused != 15 {
		t.Fatalf("refused %d spellings, want 15", refused)
	}
	if !strings.Contains(pairing.ErrBlobNonCanonical.Error(), "last character") {
		t.Errorf("ErrBlobNonCanonical = %q, want it to say the last character looks mistyped", pairing.ErrBlobNonCanonical)
	}
}

func TestBlob_RedactedWhenFormatted(t *testing.T) {
	b := fixedBlob()
	enc := b.Encode()
	leaks := map[string]string{
		"encoded blob":     enc[len(pairing.BlobPrefix):],
		"secret hex":       hex.EncodeToString(b.Secret[:]),
		"secret HEX":       strings.ToUpper(hex.EncodeToString(b.Secret[:])),
		"secret std b64":   base64.RawStdEncoding.EncodeToString(b.Secret[:]),
		"secret url b64":   base64.RawURLEncoding.EncodeToString(b.Secret[:]),
		"secret raw":       string(b.Secret[:]),
		"secret decimal":   strings.Trim(fmt.Sprint(b.Secret[:]), "[]"),
		"secret json":      strings.Trim(strings.ReplaceAll(fmt.Sprint(b.Secret[:]), " ", ","), "[]"),
		"secret go syntax": strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", b.Secret[:]), "[]byte{"), "}"),
	}
	check := func(t *testing.T, out string) {
		t.Helper()
		for name, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Errorf("output leaks %s: %q", name, out)
			}
		}
		if !strings.Contains(strings.ToLower(out), "redacted") {
			t.Errorf("output has no redacted marker: %q", out)
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		t.Run("fmt "+verb, func(t *testing.T) {
			check(t, fmt.Sprintf(verb, b))
			check(t, fmt.Sprintf(verb, &b))
		})
	}
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"slog text": func(w *bytes.Buffer) slog.Handler { return slog.NewTextHandler(w, nil) },
		"slog json": func(w *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(mk(&buf)).Info("pairing", "blob", b, "ptr", &b)
			check(t, buf.String())
		})
	}
	t.Run("json.Marshal", func(t *testing.T) {
		for _, v := range []any{b, &b, struct{ B pairing.Blob }{b}} {
			out, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			check(t, string(out))
		}
	})
	if got, err := pairing.ParseBlob(enc); err != nil || got != b || got.Encode() != enc {
		t.Fatalf("redaction changed the blob itself: %v", err)
	}
}

func TestNewBlob_RejectsBadPin(t *testing.T) {
	pin := sha256.Sum256([]byte("k"))
	canon := base64.StdEncoding.EncodeToString(pin[:])
	// Non-canonical std spelling of the same digest: flip unused low bits of the char before "=".
	i := len(canon) - 2
	idx := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", canon[i])
	nonCanon := canon[:i] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[idx|1]) + canon[i+1:]
	if nonCanon == canon {
		t.Fatal("test bug: nonCanon == canon")
	}
	cases := map[string]string{
		"not base64":     "!!!not-base64!!!",
		"31 bytes":       base64.StdEncoding.EncodeToString(pin[:31]),
		"33 bytes":       base64.StdEncoding.EncodeToString(append(pin[:], 0)),
		"url alphabet":   base64.URLEncoding.EncodeToString(pin[:]),
		"surrounding ws": " " + canon + "\n",
		"non-canonical":  nonCanon,
		"empty":          "",
	}
	if base64.URLEncoding.EncodeToString(pin[:]) == canon {
		delete(cases, "url alphabet")
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := pairing.NewBlob(in); err == nil {
				t.Fatalf("NewBlob(%q) accepted", in)
			}
		})
	}
	b, err := pairing.NewBlob(canon)
	if err != nil {
		t.Fatalf("canonical pin refused: %v", err)
	}
	if b.ListenerPin != pin || b.PinB64() != canon {
		t.Fatal("pin not carried")
	}
}

func TestNewBlob_SecretIsFresh(t *testing.T) {
	pin := sha256.Sum256([]byte("k"))
	canon := base64.StdEncoding.EncodeToString(pin[:])
	seen := map[[16]byte]bool{}
	for range 64 {
		b, err := pairing.NewBlob(canon)
		if err != nil {
			t.Fatal(err)
		}
		if b.Secret == ([16]byte{}) {
			t.Fatal("zero secret")
		}
		if seen[b.Secret] {
			t.Fatal("secret repeated")
		}
		seen[b.Secret] = true
	}
}

func FuzzParseBlob(f *testing.F) {
	good := fixedBlob().Encode()
	body := good[len(pairing.BlobPrefix):]
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	f.Add(good)
	for _, seed := range []string{
		"", "QLJ1-", body, "qlj1-" + body, " " + good, "QLJ2-" + body,
		"QLJ1-+" + body[1:], "QLJ1-/" + body[1:], good + "==", good + "=", good + "\n", good + "\r\n", good + " ",
		"QLJ1-" + body[:20] + "\n" + body[20:],
		"QLJ1-" + base64.RawURLEncoding.EncodeToString(raw[:48]),
		"QLJ1-" + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), 0)),
		"QLJ1-" + base64.RawURLEncoding.EncodeToString(append([]byte{0x00}, raw[1:]...)),
		"QLJ1-" + base64.RawURLEncoding.EncodeToString(append([]byte{0x02}, raw[1:]...)),
		"QLJ1-" + base64.RawURLEncoding.EncodeToString(append([]byte{0xff}, raw[1:]...)),
	} {
		f.Add(seed)
	}
	last := strings.IndexByte(b64url, good[len(good)-1]) &^ 0x0f
	for low := range 16 {
		f.Add(good[:len(good)-1] + string(b64url[last|low]))
	}
	sentinels := []error{pairing.ErrBlobPrefix, pairing.ErrBlobDecode, pairing.ErrBlobLength, pairing.ErrBlobVersion, pairing.ErrBlobNonCanonical}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := pairing.ParseBlob(s)
		if err != nil {
			matched := 0
			for _, e := range sentinels {
				if errors.Is(err, e) {
					matched++
					if err.Error() != e.Error() {
						t.Fatalf("error text %q adds material beyond the sentinel %q", err, e)
					}
				}
			}
			if matched != 1 {
				t.Fatalf("error %v matches %d blob sentinels, want exactly 1", err, matched)
			}
			if rest, ok := strings.CutPrefix(s, pairing.BlobPrefix); ok && len(rest) >= 8 && strings.Contains(err.Error(), rest) {
				t.Fatalf("error text contains the blob body: %v", err)
			}
			return
		}
		if b.Encode() != s {
			t.Fatalf("accepted %q but Encode() = %q", s, b.Encode())
		}
	})
}
