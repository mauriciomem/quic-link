/**
 * @spec-handoff
 * @interface NewBlob(listenerPinB64 string) (Blob, error); (Blob) Encode() string; ParseBlob(s string) (Blob, error); (Blob) PinB64() string
 *   (Blob) Secret() [SecretLen]byte; (Blob) ListenerPin() [sha256.Size]byte
 * @behavior
 *   - Encode = "QLJ1-" + base64.RawURLEncoding(0x01 || Secret[16] || ListenerPin[32]); always BlobLen (71) chars
 *   - ParseBlob(Encode(b)) has the same accessors and the same Encode as b; Blob is not comparable; PinB64 is base64.StdEncoding of ListenerPin
 *   - NewBlob fills Secret from crypto/rand; pin must be std-b64, 32 bytes, canonical (no normalization)
 * @edge-cases
 *   - Order: prefix -> decode -> length != 49 -> version != 0x01 -> re-encode != input -> all-zero secret
 *   - Errors (errors.Is-distinct): ErrBlobPrefix, ErrBlobDecode, ErrBlobLength, ErrBlobVersion, ErrBlobNonCanonical, ErrBlobZeroSecret
 *   - 15 non-canonical spellings of the last char refused; ErrBlobNonCanonical text says the "last character" looks mistyped
 *   - No trimming; every ParseBlob error is exactly one sentinel (no blob material in error text)
 *   - Redaction: fmt (%v %+v %#v %s), slog (Text/JSON via LogValue) and json.Marshal of a Blob show a "redacted"
 *     marker and never the secret (raw/hex/base64) nor the encoded blob body
 *   - Blob fields are unexported with accessors Secret() [SecretLen]byte (zero if unset) and ListenerPin() [32]byte;
 *     the secret is reachable only through a function-valued field, so a struct holding a Blob in an UNEXPORTED field
 *     (where fmt cannot call Blob's methods) prints no secret under any fmt verb (%v %+v %#v %s %q %t %c %e %f %g %U %O %x %d) nor in slog text
 *   - cbor.Marshal and gob of a Blob (value, pointer, or inside a struct) carry no secret bytes;
 *     gob refusing with "no exported fields" is acceptable
 *   - Secret()/ListenerPin() return what NewBlob was given / ParseBlob decoded; Secret() returns a copy
 *   - Zero Blob: Secret() is all-zero (no panic), Encode carries the zero secret, ParseBlob of that encoding is ErrBlobZeroSecret, VerifyProof refuses a zero key
 *   - Tests reach the secret only through Encode/ParseBlob and the accessors, never through Blob's fields
 * @see ../identity/pin.go (ParsePinStrict)
 */

package pairing_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mauriciomem/quic-link/internal/pairing"
)

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

var (
	fixedSecret = func() (s [pairing.SecretLen]byte) {
		for i := range s {
			s[i] = byte(0xA0 + i)
		}
		return s
	}()
	fixedPin = sha256.Sum256([]byte("listener spki"))
)

// fixedBlob builds the blob through the public decoder, so these tests do not
// depend on Blob's field layout.
func fixedBlob() pairing.Blob {
	p := append(append([]byte{pairing.BlobVersion}, fixedSecret[:]...), fixedPin[:]...)
	b, err := pairing.ParseBlob(pairing.BlobPrefix + base64.RawURLEncoding.EncodeToString(p))
	if err != nil {
		panic(err)
	}
	return b
}

// payloadOf returns the secret and listener pin carried by b, read back from
// its encoding.
func payloadOf(t testing.TB, b pairing.Blob) (secret [pairing.SecretLen]byte, pin [sha256.Size]byte) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(b.Encode(), pairing.BlobPrefix))
	if err != nil || len(raw) != 1+pairing.SecretLen+sha256.Size {
		t.Fatalf("decode own encoding: len %d err %v", len(raw), err)
	}
	copy(secret[:], raw[1:])
	copy(pin[:], raw[1+pairing.SecretLen:])
	return secret, pin
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
	want := append(append([]byte{0x01}, fixedSecret[:]...), fixedPin[:]...)
	if !bytes.Equal(raw, want) {
		t.Fatalf("payload layout mismatch:\n got %x\nwant %x", raw, want)
	}
	got, err := pairing.ParseBlob(s)
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}
	if gs, gp := payloadOf(t, got); got.Encode() != s || gs != fixedSecret || gp != fixedPin {
		t.Fatalf("round trip mismatch")
	}
	if got.PinB64() != base64.StdEncoding.EncodeToString(fixedPin[:]) {
		t.Fatalf("PinB64 = %q", got.PinB64())
	}
}

func TestParseBlob_Defects(t *testing.T) {
	b := fixedBlob()
	good := b.Encode()
	body := good[5:]
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	badVer := append([]byte{0x02}, raw[1:]...)
	zeroSecret := append(append([]byte{pairing.BlobVersion}, make([]byte, pairing.SecretLen)...), fixedPin[:]...)
	secretB64 := base64.RawURLEncoding.EncodeToString(fixedSecret[:])

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
		{"all-zero secret", "QLJ1-" + base64.RawURLEncoding.EncodeToString(zeroSecret), pairing.ErrBlobZeroSecret},
	}
	all := []error{pairing.ErrBlobPrefix, pairing.ErrBlobDecode, pairing.ErrBlobLength, pairing.ErrBlobVersion, pairing.ErrBlobNonCanonical, pairing.ErrBlobZeroSecret}
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
	leaks := secretRenderings(enc)
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
	if got, err := pairing.ParseBlob(enc); err != nil || got.Encode() != enc {
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
	if _, got := payloadOf(t, b); got != pin || b.PinB64() != canon {
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
		secret, _ := payloadOf(t, b)
		if secret == ([16]byte{}) {
			t.Fatal("zero secret")
		}
		if seen[secret] {
			t.Fatal("secret repeated")
		}
		seen[secret] = true
	}
}

// secretRenderings lists the text forms in which fixedSecret (and the
// encoded blob body enc) could appear in formatted output.
func secretRenderings(enc string) map[string]string {
	return map[string]string{
		"encoded blob":     enc[len(pairing.BlobPrefix):],
		"secret hex":       hex.EncodeToString(fixedSecret[:]),
		"secret HEX":       strings.ToUpper(hex.EncodeToString(fixedSecret[:])),
		"secret std b64":   base64.RawStdEncoding.EncodeToString(fixedSecret[:]),
		"secret url b64":   base64.RawURLEncoding.EncodeToString(fixedSecret[:]),
		"secret raw":       string(fixedSecret[:]),
		"secret decimal":   strings.Trim(fmt.Sprint(fixedSecret[:]), "[]"),
		"secret json":      strings.Trim(strings.ReplaceAll(fmt.Sprint(fixedSecret[:]), " ", ","), "[]"),
		"secret go syntax": strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", fixedSecret[:]), "[]byte{"), "}"),
	}
}

// blobHolder keeps a Blob in an unexported field. fmt cannot call methods
// through an unexported field, so Blob's String/Format/LogValue redaction does
// not apply here: only the shape of Blob's own fields protects the secret.
type blobHolder struct {
	name string
	b    pairing.Blob
}

func TestBlob_NotPrintedThroughUnexportedField(t *testing.T) {
	b := fixedBlob()
	leaks := secretRenderings(b.Encode())
	check := func(t *testing.T, out string) {
		t.Helper()
		for name, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Errorf("output leaks %s: %q", name, out)
			}
		}
	}
	h := blobHolder{name: "h", b: b}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%t", "%c", "%e", "%f", "%g", "%U", "%O", "%x", "%d"} {
		t.Run("fmt "+verb, func(t *testing.T) {
			check(t, fmt.Sprintf(verb, h))
			check(t, fmt.Sprintf(verb, &h))
			check(t, fmt.Sprintf(verb, []blobHolder{h}))
		})
	}
	t.Run("slog text", func(t *testing.T) {
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("pairing", "holder", h, "ptr", &h)
		check(t, buf.String())
	})
	t.Run("control: the holder is printed field by field", func(t *testing.T) {
		if out := fmt.Sprintf("%+v", h); !strings.Contains(out, "name:h") {
			t.Fatalf("%%+v of the holder = %q: this test does not observe field-by-field printing", out)
		}
	})
}

// encodedForms lists the byte forms in which fixedSecret could appear in a
// binary encoding: contiguous (a byte string) or element by element as CBOR
// or gob unsigned integers.
func encodedForms() map[string][]byte {
	var cborUints, gobUints []byte
	for _, c := range fixedSecret {
		cborUints = append(cborUints, 0x18, c) // every fixedSecret byte is >= 24
		gobUints = append(gobUints, 0xFF, c)   // and >= 128
	}
	return map[string][]byte{"raw bytes": fixedSecret[:], "CBOR uints": cborUints, "gob uints": gobUints}
}

func TestBlob_NotSerializedByReflectionEncoders(t *testing.T) {
	b := fixedBlob()
	check := func(t *testing.T, what string, out []byte) {
		t.Helper()
		for form, leak := range encodedForms() {
			if bytes.Contains(out, leak) {
				t.Errorf("%s leaks the secret as %s: %x", what, form, out)
			}
		}
	}
	values := map[string]any{"value": b, "pointer": &b, "exported field": struct{ B pairing.Blob }{b}}
	for name, v := range values {
		t.Run("cbor/"+name, func(t *testing.T) {
			out, err := cbor.Marshal(v)
			if err != nil {
				return // nothing written, nothing leaked
			}
			check(t, "cbor.Marshal", out)
		})
		t.Run("gob/"+name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := gob.NewEncoder(&buf).Encode(v); err != nil {
				if !strings.Contains(err.Error(), "no exported fields") {
					t.Errorf("gob: unexpected error %v", err)
				}
				return
			}
			check(t, "gob", buf.Bytes())
		})
	}
	t.Run("control: the forms are detectable", func(t *testing.T) {
		out, err := cbor.Marshal(struct{ S [pairing.SecretLen]byte }{fixedSecret})
		if err != nil || !bytes.Contains(out, fixedSecret[:]) {
			t.Fatalf("cbor of a plain secret array not detected: %x %v", out, err)
		}
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(struct{ S [pairing.SecretLen]byte }{fixedSecret}); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, leak := range encodedForms() {
			found = found || bytes.Contains(buf.Bytes(), leak)
		}
		if !found {
			t.Fatalf("gob of a plain secret array not detected: %x", buf.Bytes())
		}
	})
}

func TestBlob_AccessorsReturnCarriedValues(t *testing.T) {
	t.Run("ParseBlob", func(t *testing.T) {
		b := fixedBlob()
		if b.Secret() != fixedSecret {
			t.Errorf("Secret() = %x, want %x", b.Secret(), fixedSecret)
		}
		if b.ListenerPin() != fixedPin {
			t.Errorf("ListenerPin() = %x, want %x", b.ListenerPin(), fixedPin)
		}
	})
	t.Run("NewBlob and ParseBlob(Encode)", func(t *testing.T) {
		pin := sha256.Sum256([]byte("accessor listener"))
		b, err := pairing.NewBlob(base64.StdEncoding.EncodeToString(pin[:]))
		if err != nil {
			t.Fatal(err)
		}
		encSecret, encPin := payloadOf(t, b)
		if b.ListenerPin() != pin || encPin != pin {
			t.Errorf("ListenerPin() = %x, encoded %x, want %x", b.ListenerPin(), encPin, pin)
		}
		if b.Secret() != encSecret || b.Secret() == ([pairing.SecretLen]byte{}) {
			t.Errorf("Secret() = %x, encoded %x, want the encoded non-zero secret", b.Secret(), encSecret)
		}
		got, err := pairing.ParseBlob(b.Encode())
		if err != nil {
			t.Fatal(err)
		}
		if got.Secret() != b.Secret() || got.ListenerPin() != pin {
			t.Errorf("ParseBlob(Encode(b)) accessors = %x/%x, want %x/%x", got.Secret(), got.ListenerPin(), b.Secret(), pin)
		}
	})
	t.Run("Blob is not comparable", func(t *testing.T) {
		if reflect.TypeOf(pairing.Blob{}).Comparable() {
			t.Errorf("pairing.Blob is comparable: == would compare secret identity, not the blob")
		}
	})
}

func TestBlob_SecretAccessorReturnsACopy(t *testing.T) {
	t.Run("mutating the result leaves the blob unchanged", func(t *testing.T) {
		b := fixedBlob()
		enc := b.Encode()
		s := b.Secret()
		for i := range s {
			s[i] ^= 0xFF
		}
		if b.Secret() != fixedSecret {
			t.Errorf("second Secret() = %x, want %x", b.Secret(), fixedSecret)
		}
		if b.Encode() != enc {
			t.Errorf("Encode changed after mutating the Secret() result")
		}
	})
	t.Run("zero Blob has an all-zero secret", func(t *testing.T) {
		var b pairing.Blob
		if b.Secret() != ([pairing.SecretLen]byte{}) {
			t.Errorf("zero Blob Secret() = %x, want all zero", b.Secret())
		}
		if b.ListenerPin() != ([sha256.Size]byte{}) {
			t.Errorf("zero Blob ListenerPin() = %x, want all zero", b.ListenerPin())
		}
		if secret, _ := payloadOf(t, b); secret != ([pairing.SecretLen]byte{}) {
			t.Errorf("zero Blob encodes secret %x, want all zero", secret)
		}
		if _, err := pairing.ParseBlob(b.Encode()); !errors.Is(err, pairing.ErrBlobZeroSecret) {
			t.Errorf("ParseBlob(zero Blob encoding) = %v, want ErrBlobZeroSecret", err)
		}
	})
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
	sentinels := []error{pairing.ErrBlobPrefix, pairing.ErrBlobDecode, pairing.ErrBlobLength, pairing.ErrBlobVersion, pairing.ErrBlobNonCanonical, pairing.ErrBlobZeroSecret}
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
