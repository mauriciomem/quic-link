package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/mauriciomem/quic-link/internal/identity"
)

const (
	// BlobPrefix marks a version-1 join blob.
	BlobPrefix = "QLJ1-"
	// BlobVersion is the first payload byte of a version-1 join blob.
	BlobVersion = 0x01
	// SecretLen is the size of the join secret in bytes.
	SecretLen = 16

	payloadLen = 1 + SecretLen + sha256.Size

	// BlobLen is the length of an encoded join blob in characters.
	BlobLen = len(BlobPrefix) + (payloadLen*8+5)/6
)

// Sentinel errors returned by ParseBlob, always unwrapped. Their text never
// includes blob material, because the blob carries the join secret.
var (
	ErrBlobPrefix       = errors.New("pairing: join blob lacks the QLJ1- prefix")
	ErrBlobDecode       = errors.New("pairing: join blob is not unpadded base64url")
	ErrBlobLength       = errors.New("pairing: join blob has the wrong length")
	ErrBlobVersion      = errors.New("pairing: join blob has an unknown version")
	ErrBlobNonCanonical = errors.New("blob: last character looks mistyped (not canonically encoded)")
	ErrBlobZeroSecret   = errors.New("pairing: join blob has an all-zero secret")
)

// Blob is the decoded join blob: a one-time secret and the listener's pin.
//
// Its fields are unexported and the secret is reachable only by calling a
// function held in one of them. Where Blob's redacting methods are bypassed -
// a Blob inside an unexported struct field - fmt prints at most a function
// address, for every verb, and reflection encoders (CBOR, gob) see no
// exported fields.
//
// Blob is not comparable: compare Encode() or the accessors. The zero Blob
// carries an all-zero secret, which ParseBlob and VerifyProof refuse.
type Blob struct {
	secret      func() *[SecretLen]byte // nil in the zero Blob
	listenerPin [sha256.Size]byte
}

// holdSecret returns a function that yields s. fmt and reflection print a
// function as an address and never call it.
func holdSecret(s *[SecretLen]byte) func() *[SecretLen]byte {
	return func() *[SecretLen]byte { return s }
}

// Secret returns a copy of the join secret, or the zero value for a zero Blob.
func (b Blob) Secret() [SecretLen]byte {
	if b.secret == nil {
		return [SecretLen]byte{}
	}
	return *b.secret()
}

// ListenerPin returns the listener's pin as raw SHA-256 bytes.
func (b Blob) ListenerPin() [sha256.Size]byte { return b.listenerPin }

// NewBlob returns a blob for the listener whose canonical standard-base64 pin
// is listenerPinB64, with a fresh secret from crypto/rand. The pin is held to
// identity.ParsePinStrict: no trimming, no repair of non-canonical spellings.
func NewBlob(listenerPinB64 string) (Blob, error) {
	pin, err := identity.ParsePinStrict(listenerPinB64)
	if err != nil {
		return Blob{}, fmt.Errorf("pairing: listener pin: %w", err)
	}
	secret := new([SecretLen]byte)
	b := Blob{secret: holdSecret(secret)}
	raw, err := base64.StdEncoding.DecodeString(pin)
	if err != nil {
		return Blob{}, fmt.Errorf("pairing: listener pin: %w", err)
	}
	copy(b.listenerPin[:], raw)
	if _, err := rand.Read(secret[:]); err != nil {
		return Blob{}, fmt.Errorf("pairing: generating join secret: %w", err)
	}
	return b, nil
}

// Encode returns "QLJ1-" + base64url(0x01 || Secret || ListenerPin), unpadded.
// A zero Blob encodes an all-zero secret.
func (b Blob) Encode() string {
	var p [payloadLen]byte
	p[0] = BlobVersion
	secret := b.Secret()
	copy(p[1:], secret[:])
	copy(p[1+SecretLen:], b.listenerPin[:])
	return BlobPrefix + base64.RawURLEncoding.EncodeToString(p[:])
}

// PinB64 returns the listener pin in its standard-base64 form.
func (b Blob) PinB64() string {
	return base64.StdEncoding.EncodeToString(b.listenerPin[:])
}

// ParseBlob decodes s exactly as given. It never trims or normalizes: any
// spelling other than the one Encode would produce is refused, including
// non-zero unused trailing bits. An all-zero secret, which no listener
// accepts, is ErrBlobZeroSecret.
func ParseBlob(s string) (Blob, error) {
	body, ok := strings.CutPrefix(s, BlobPrefix)
	if !ok {
		return Blob{}, ErrBlobPrefix
	}
	// encoding/base64 silently skips '\r' and '\n', so the alphabet is
	// checked here rather than left to the decoder.
	if strings.IndexFunc(body, notBase64URL) >= 0 {
		return Blob{}, ErrBlobDecode
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Blob{}, ErrBlobDecode
	}
	if len(raw) != payloadLen {
		return Blob{}, ErrBlobLength
	}
	if raw[0] != BlobVersion {
		return Blob{}, ErrBlobVersion
	}
	secret := new([SecretLen]byte)
	copy(secret[:], raw[1:1+SecretLen])
	b := Blob{secret: holdSecret(secret)}
	copy(b.listenerPin[:], raw[1+SecretLen:])
	if b.Encode() != s {
		return Blob{}, ErrBlobNonCanonical
	}
	// Checked last so every other defect keeps its own error.
	if b.Secret() == ([SecretLen]byte{}) {
		return Blob{}, ErrBlobZeroSecret
	}
	return b, nil
}

func notBase64URL(r rune) bool {
	return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
}

// blobRedacted is what every formatting path prints instead of the blob.
const blobRedacted = "pairing.Blob{redacted}"

// String redacts the blob: it carries the join secret.
func (b Blob) String() string { return blobRedacted }

// GoString redacts the blob for %#v.
func (b Blob) GoString() string { return blobRedacted }

// Format redacts the blob for every fmt verb, including %+v and %x, which
// would otherwise print the fields.
func (b Blob) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, blobRedacted) }

// LogValue redacts the blob in slog output.
func (b Blob) LogValue() slog.Value { return slog.StringValue(blobRedacted) }

// MarshalJSON redacts the blob in JSON output.
func (b Blob) MarshalJSON() ([]byte, error) { return json.Marshal(blobRedacted) }
