package pairing

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	// MethodTokenHMACv1 is the only pairing proof method this version accepts.
	MethodTokenHMACv1 = "token-hmac-v1"
	// MaxLabelLen is the maximum length of a pairing label in bytes.
	MaxLabelLen = 64
)

// Sentinel errors returned by ParsePairRequest.
var (
	ErrBadHeader         = errors.New("pairing: malformed pair request")
	ErrUnsupportedMethod = errors.New("pairing: unsupported pairing method")
)

// Status is the pairing response status code.
type Status uint

// Pairing response statuses.
const (
	StatusOK Status = iota
	StatusBadProof
	StatusWindowClosed
	StatusRateLimited
	StatusBadHeader
	StatusUnsupportedMethod
	StatusConflict
)

var statusNames = [...]string{"ok", "bad_proof", "window_closed", "rate_limited", "bad_header", "unsupported_method", "conflict"}

// String returns the wire-spec name of s.
func (s Status) String() string {
	if s.valid() {
		return statusNames[s]
	}
	return fmt.Sprintf("status(%d)", uint(s))
}

func (s Status) valid() bool { return uint(s) < uint(len(statusNames)) }

// PairRequest is the client's pairing request.
type PairRequest struct {
	Method string `cbor:"method"`
	Label  string `cbor:"label,omitempty"`
	Proof  []byte `cbor:"proof"`
}

// PairResponse is the server's reply to a PairRequest.
type PairResponse struct {
	Status Status `cbor:"status"`
	Msg    string `cbor:"msg"`
}

var (
	encMode = mustEncMode()
	// decMode is strict, following the internal/ipc precedent: unknown keys,
	// duplicate keys, indefinite lengths and tags are all refused, and keys
	// match field names case-sensitively (the library default does not).
	decMode = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("pairing: build CBOR enc mode: %v", err))
	}
	return em
}

func mustDecMode() cbor.DecMode {
	dm, err := cbor.DecOptions{
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   4,
		MaxMapPairs:       16,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("pairing: build CBOR dec mode: %v", err))
	}
	return dm
}

// Marshal encodes r with core deterministic CBOR.
func (r PairRequest) Marshal() ([]byte, error) { return encMode.Marshal(r) }

// Marshal encodes r with core deterministic CBOR.
func (r PairResponse) Marshal() ([]byte, error) { return encMode.Marshal(r) }

// ParsePairRequest strictly decodes and validates a pair request. Errors wrap
// ErrBadHeader or, for a well-formed request naming another method,
// ErrUnsupportedMethod.
func ParsePairRequest(data []byte) (PairRequest, error) {
	var r PairRequest
	if err := decMode.Unmarshal(data, &r); err != nil {
		return PairRequest{}, fmt.Errorf("%w: %v", ErrBadHeader, err)
	}
	if r.Method == "" {
		return PairRequest{}, fmt.Errorf("%w: missing method", ErrBadHeader)
	}
	if r.Method != MethodTokenHMACv1 {
		return PairRequest{}, ErrUnsupportedMethod
	}
	if len(r.Proof) != ProofLength {
		return PairRequest{}, fmt.Errorf("%w: proof length %d", ErrBadHeader, len(r.Proof))
	}
	if err := validateLabel(r.Label); err != nil {
		return PairRequest{}, err
	}
	return r, nil
}

// validateLabel allows at most MaxLabelLen printable ASCII bytes, excluding
// '#' (reserved as the comment marker in the authorized-keys file).
func validateLabel(l string) error {
	if len(l) > MaxLabelLen {
		return fmt.Errorf("%w: label longer than %d bytes", ErrBadHeader, MaxLabelLen)
	}
	for i := 0; i < len(l); i++ {
		if c := l[i]; c < 0x20 || c > 0x7e || c == '#' {
			return fmt.Errorf("%w: label byte 0x%02x not allowed", ErrBadHeader, c)
		}
	}
	return nil
}

// ParsePairResponse strictly decodes a pair response and refuses unknown
// status values.
func ParsePairResponse(data []byte) (PairResponse, error) {
	var r PairResponse
	if err := decMode.Unmarshal(data, &r); err != nil {
		return PairResponse{}, fmt.Errorf("pairing: malformed pair response: %w", err)
	}
	if !r.Status.valid() {
		return PairResponse{}, fmt.Errorf("pairing: unknown response status %d", uint(r.Status))
	}
	return r, nil
}

// StatusForParseError maps a ParsePairRequest error to the response status
// the server sends back; a nil error maps to StatusOK.
func StatusForParseError(err error) Status {
	if err == nil {
		return StatusOK
	}
	if errors.Is(err, ErrUnsupportedMethod) {
		return StatusUnsupportedMethod
	}
	return StatusBadHeader
}

// ExitCodeForPairing maps a response status to the client's process exit
// code: 0 on success, 6 for a refused pairing, 1 for a protocol error or a
// status this version does not know.
func ExitCodeForPairing(s Status) int {
	switch s {
	case StatusOK:
		return 0
	case StatusBadProof, StatusWindowClosed, StatusRateLimited, StatusConflict:
		return 6
	default:
		return 1
	}
}
