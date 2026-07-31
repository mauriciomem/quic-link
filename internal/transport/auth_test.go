// Package transport_test contains black-box tests for the transport package.
// This file tests the IsAuthFailed predicate and AuthError constructor together,
// specifically the idempotence property that was broken by the old design.
package transport_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mauriciomem/quic-link/internal/transport"
	quic "github.com/quic-go/quic-go"
)

// makeTransportError builds a *quic.TransportError with the given code.
// The TransportError struct fields are exported, so we can construct one
// directly without needing a live QUIC connection.
func makeTransportError(code quic.TransportErrorCode) error {
	return &quic.TransportError{ErrorCode: code}
}

// tlsAlertBadCertificate is TLS alert 42 (bad_certificate), mapped to QUIC
// transport error code 0x100 + 42 = 0x12a. This is the alert the agent sends
// when it rejects a client pin via VerifyPeerCertificate.
const tlsAlertBadCertificate quic.TransportErrorCode = 0x12a

// tlsAlertNoAppProtocol is the ALPN-mismatch alert (TLS 120, QUIC 0x178).
// This must NOT be classified as an auth failure — it signals mismatched
// binary versions, not a wrong pin.
const tlsAlertNoAppProtocol quic.TransportErrorCode = 0x178

// TestIsAuthFailed_RawTransportError verifies that a raw *quic.TransportError
// in the TLS-alert range (the not-yet-classified form) is recognised.
// This is the form that arrives directly from quic-go before any classification.
func TestIsAuthFailed_RawTransportError(t *testing.T) {
	t.Parallel()
	err := makeTransportError(tlsAlertBadCertificate)
	if !transport.IsAuthFailed(err) {
		t.Errorf("IsAuthFailed(%v) = false, want true for raw TLS-alert TransportError", err)
	}
}

// TestIsAuthFailed_AlreadyClassifiedByAuthError is the regression test for the
// bug this change fixes. The old predicate (transport.AuthError(err) != nil)
// could not recognise an error that had ALREADY been through AuthError, because
// AuthError discards the *quic.TransportError and wraps only the ErrAuthFailed
// sentinel — leaving no TransportError for the next errors.As to find.
//
// IsAuthFailed must return true for the output of AuthError: a caller that
// receives an already-classified error from a helper (e.g. tunnel.OpenControl)
// must be able to detect it as an auth failure without caring whether the
// classification happened upstream or locally.
func TestIsAuthFailed_AlreadyClassifiedByAuthError(t *testing.T) {
	t.Parallel()
	raw := makeTransportError(tlsAlertBadCertificate)

	// Classify the raw error (as tunnel.OpenControl does on the close cause).
	classified := transport.AuthError(raw)
	if classified == nil {
		t.Fatal("AuthError returned nil for a TLS-alert-range error; test setup broken")
	}

	// The classified error must wrap ErrAuthFailed but no longer carry a TransportError.
	if !errors.Is(classified, transport.ErrAuthFailed) {
		t.Errorf("classified error does not wrap ErrAuthFailed: %v", classified)
	}
	var te *quic.TransportError
	if errors.As(classified, &te) {
		t.Errorf("classified error still carries a *quic.TransportError — test assumption wrong: %v", classified)
	}

	// The key assertion: IsAuthFailed must still return true.
	if !transport.IsAuthFailed(classified) {
		t.Errorf("IsAuthFailed(AuthError(raw)) = false, want true\n"+
			"This is the exact bug: the old predicate (AuthError(err) != nil) "+
			"returns nil here because AuthError strips the *quic.TransportError "+
			"that its own errors.As needs to find on the next call.\n"+
			"classified error: %v", classified)
	}
}

// TestIsAuthFailed_AfterClassifyDialError verifies that IsAuthFailed returns
// true for the error produced by classifyDialError on a TLS-alert-range
// TransportError. classifyDialError is unexported but its output reaches
// callers through Transport.Dial; we replicate its wrapping logic here
// to exercise the same error shape that Dial callers receive.
//
// classifyDialError wraps ErrAuthFailed with %w and also wraps the original
// *quic.TransportError with the second %w — so errors.Is, errors.As, and the
// IsAuthFailed sentinel check all work on its output. This test confirms the
// sentinel path works correctly on that shape.
func TestIsAuthFailed_AfterClassifyDialError(t *testing.T) {
	t.Parallel()

	// Replicate the wrapping classifyDialError produces for an auth rejection.
	// The real function is unexported, but its output shape for the auth-
	// rejection branch is:
	//   fmt.Errorf("%w ... %w", ErrAuthFailed, <original TransportError>)
	// errors.Is(err, ErrAuthFailed) returns true on this shape.
	rawTE := makeTransportError(tlsAlertBadCertificate)
	classified := fmt.Errorf(
		"%w (TLS error 0x%x; verify --pin and --authorized-client): %w",
		transport.ErrAuthFailed, uint64(tlsAlertBadCertificate), rawTE,
	)

	if !errors.Is(classified, transport.ErrAuthFailed) {
		t.Errorf("test setup: classified does not wrap ErrAuthFailed: %v", classified)
	}
	if !transport.IsAuthFailed(classified) {
		t.Errorf("IsAuthFailed(classifyDialError-shaped error) = false, want true: %v", classified)
	}
}

// TestIsAuthFailed_FalseForUnrelatedErrors verifies the cases that must NOT be
// reported as auth failures. Each of these is a distinct failure class with its
// own exit code; misclassifying any of them as auth failure would send the
// operator in the wrong direction.
func TestIsAuthFailed_FalseForUnrelatedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "plain unrelated error",
			err:  errors.New("something went wrong"),
		},
		{
			name: "ErrUnreachable sentinel",
			err:  transport.ErrUnreachable,
		},
		{
			name: "ErrUnreachable wrapped",
			err:  fmt.Errorf("handshake timeout: %w", transport.ErrUnreachable),
		},
		{
			name: "ALPN-mismatch TransportError (alertNoAppProtocol 0x178)",
			// This code means mismatched binary versions — operator must
			// rebuild both ends. It is deliberately excluded from the
			// TLS-alert range treated as an auth failure.
			err: makeTransportError(tlsAlertNoAppProtocol),
		},
		{
			name: "nil error",
			err:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if transport.IsAuthFailed(tc.err) {
				t.Errorf("IsAuthFailed(%v) = true, want false", tc.err)
			}
		})
	}
}

// TestIsAuthFailed_IdempotenceProperty states the idempotence invariant
// explicitly: for any error e where IsAuthFailed(e) is true AND AuthError(e)
// returns a non-nil classified error, IsAuthFailed of that classified error
// must also be true.
//
// This is the property the old predicate (transport.AuthError(err) != nil)
// violated: applying AuthError a second time returned nil because the
// TransportError had been discarded, so the predicate could not recognize its
// own output.
func TestIsAuthFailed_IdempotenceProperty(t *testing.T) {
	t.Parallel()

	// A raw TransportError that AuthError can classify.
	seed := makeTransportError(tlsAlertBadCertificate)

	if !transport.IsAuthFailed(seed) {
		t.Fatal("seed error: IsAuthFailed returned false; test setup broken")
	}

	classified := transport.AuthError(seed)
	if classified == nil {
		t.Fatal("AuthError(seed) returned nil; test setup broken")
	}

	// Idempotence: the predicate must return the same answer on the classified
	// form as on the raw form.
	if !transport.IsAuthFailed(classified) {
		t.Errorf(
			"idempotence violated: IsAuthFailed(AuthError(e)) = false, but IsAuthFailed(e) = true\n"+
				"raw error:        %v\n"+
				"classified error: %v\n\n"+
				"Old predicate (AuthError(err) != nil) fails this test because AuthError\n"+
				"strips the *quic.TransportError, leaving no TransportError for a second\n"+
				"errors.As to find. IsAuthFailed fixes this by checking errors.Is(err,\n"+
				"ErrAuthFailed) first, which succeeds on the classified form.",
			seed, classified,
		)
	}
}

// TestOldPredicateFailsIdempotence demonstrates, using a local replica of the
// old predicate, that it genuinely fails the idempotence property. This is
// evidence — not just reasoning — that the bug was real and the fix is
// necessary.
//
// The old predicate was:
//
//	func isAuthFailed(err error) bool {
//	    return errors.Is(err, transport.ErrAuthFailed) || transport.AuthError(err) != nil
//	}
//
// The first clause (errors.Is) handles the classified form correctly. The
// second clause (AuthError(err) != nil) was intended to catch the raw
// TransportError form, but it was used as THE WHOLE predicate at call sites
// where only the second clause ran (because the error didn't yet wrap
// ErrAuthFailed). After tunnel.OpenControl classified the error, the outer
// call in the pool received only the classified form, and a naive call to
// AuthError on that produced nil — making the pool think no auth failure
// occurred and retry indefinitely.
//
// This test uses only the second clause in isolation (the problematic part) to
// demonstrate the failure directly.
func TestOldPredicateFailsIdempotence(t *testing.T) {
	t.Parallel()

	// The old second clause, isolated.
	oldClause := func(err error) bool {
		return transport.AuthError(err) != nil
	}

	raw := makeTransportError(tlsAlertBadCertificate)

	// The old clause correctly identifies the raw form.
	if !oldClause(raw) {
		t.Fatal("old predicate: returned false for raw TransportError; test setup broken")
	}

	// Classify the error (as tunnel.OpenControl does).
	classified := transport.AuthError(raw)
	if classified == nil {
		t.Fatal("AuthError returned nil for raw TransportError; test setup broken")
	}

	// The old clause FAILS on the classified form: AuthError(classified) returns
	// nil because classified no longer carries a *quic.TransportError.
	if oldClause(classified) {
		t.Errorf(
			"old predicate returned true for the classified form — this contradicts " +
				"the bug report; re-examine the test or the AuthError implementation",
		)
	}
	// The test PASSES (i.e. oldClause returns false) — proving the old bug was real.
	// IsAuthFailed must return true for the same classified error.
	if !transport.IsAuthFailed(classified) {
		t.Errorf("IsAuthFailed also returned false for the classified form — the fix did not work")
	}
	t.Log("confirmed: old predicate (AuthError(err) != nil) returns false for the classified form; " +
		"IsAuthFailed returns true, as required")
}
