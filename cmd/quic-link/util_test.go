package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// flipTrailingBit returns a validly-decoding base64 spelling of the SAME
// 32-byte digest as canonical, but byte-different from it — the same
// non-strict-padding-bits construction internal/config/config_test.go's
// nonCanonicalPinSpelling uses, duplicated here because it is a small,
// self-contained test helper and this package cannot import a _test.go file
// from another package.
func flipTrailingBit(t *testing.T, canonical string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(canonical) < 2 || canonical[len(canonical)-1] != '=' {
		t.Fatalf("flipTrailingBit: %q is not a padded base64(32 bytes) pin", canonical)
	}
	idx := len(canonical) - 2
	pos := strings.IndexByte(alphabet, canonical[idx])
	if pos < 0 {
		t.Fatalf("flipTrailingBit: %q not in base64 alphabet", string(canonical[idx]))
	}
	flipped := (pos &^ 0x3) | ((pos & 0x3) ^ 0x1)
	variant := canonical[:idx] + string(alphabet[flipped]) + canonical[idx+1:]
	if variant == canonical {
		t.Fatal("flipTrailingBit: flip produced no change; test construction is broken")
	}
	rawCanon, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		t.Fatalf("flipTrailingBit: canonical does not decode: %v", err)
	}
	rawVariant, err := base64.StdEncoding.DecodeString(variant)
	if err != nil {
		t.Fatalf("flipTrailingBit: variant does not decode: %v", err)
	}
	if string(rawCanon) != string(rawVariant) {
		t.Fatalf("flipTrailingBit: variant decodes to a different digest than canonical")
	}
	return variant
}

// TestPinListSet_RefusesPaddedPin proves the flag path is now held to the
// same strict rule as the config-file path: a --authorized-client value with
// surrounding whitespace previously normalized silently (Set returned nil,
// the canonical form was stored); it must now be refused (Set returns a
// non-nil error), matching the config-file behavior at the same
// non-canonical-spelling defect.
func TestPinListSet_RefusesPaddedPin(t *testing.T) {
	canonical := mustTestPin(t)
	padded := canonical + "  "

	var p pinList
	err := p.Set(padded)
	if err == nil {
		t.Fatal("Set(padded pin): want error, got nil")
	}
	if len(p) != 0 {
		t.Errorf("Set(padded pin) failed but pinList grew to %v", []string(p))
	}
}

// TestPinListSet_RefusesNonCanonicalSpelling covers the same refusal for a
// non-canonical-but-validly-decoding base64 spelling of a valid digest — the
// case nobody types by accident, so leniency here bought nothing.
func TestPinListSet_RefusesNonCanonicalSpelling(t *testing.T) {
	canonical := mustTestPin(t)
	variant := flipTrailingBit(t, canonical)

	var p pinList
	err := p.Set(variant)
	if err == nil {
		t.Fatal("Set(non-canonical spelling): want error, got nil")
	}
	if len(p) != 0 {
		t.Errorf("Set(non-canonical spelling) failed but pinList grew to %v", []string(p))
	}
}

// TestPinListSet_AcceptsCanonicalPin is the control case: a pin already in
// its canonical form must still be accepted, unchanged, exactly as before
// this refusal was added.
func TestPinListSet_AcceptsCanonicalPin(t *testing.T) {
	canonical := mustTestPin(t)

	var p pinList
	if err := p.Set(canonical); err != nil {
		t.Fatalf("Set(canonical pin): unexpected error: %v", err)
	}
	if len(p) != 1 || p[0] != canonical {
		t.Errorf("pinList after Set(canonical) = %v, want [%q]", []string(p), canonical)
	}
}

// TestPinListSet_RejectsUnparseablePinUnchanged is a regression guard: an
// unparseable pin (never decoded correctly, canonical or not) must still be
// rejected as a decode failure, not accidentally swallowed by the new
// canonical-form check.
func TestPinListSet_RejectsUnparseablePinUnchanged(t *testing.T) {
	var p pinList
	err := p.Set("not-a-pin")
	if err == nil {
		t.Fatal("Set(garbage): want error, got nil")
	}
	if strings.Contains(err.Error(), "canonical") {
		t.Errorf("Set(garbage) reported a canonical-form error; want a decode error, got: %v", err)
	}
}
