package main

import (
	"errors"
	"testing"

	"github.com/mauriciomem/quic-link/internal/transport"
)

// TestAggregateProbeError verifies that aggregateProbeError returns the right
// sentinel (or none) depending on which accumulated errors are present, and
// that auth failure takes precedence over unreachability.
func TestAggregateProbeError(t *testing.T) {
	authErr := transport.ErrAuthFailed
	unreachErr := transport.ErrUnreachable

	cases := []struct {
		name       string
		authErr    error
		unreachErr error
		wantAuth   bool // result must wrap ErrAuthFailed
		wantUnrch  bool // result must wrap ErrUnreachable
	}{
		{
			name:     "auth only -> exits 4",
			authErr:  authErr,
			wantAuth: true,
		},
		{
			name:       "unreachable only -> exits 3",
			unreachErr: unreachErr,
			wantUnrch:  true,
		},
		{
			name:       "both -> auth takes precedence (exits 4)",
			authErr:    authErr,
			unreachErr: unreachErr,
			wantAuth:   true,
		},
		{
			name: "neither -> generic (exits 1)",
			// both nil: result must not carry either sentinel
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := aggregateProbeError(3, tc.authErr, tc.unreachErr)
			if err == nil {
				t.Fatal("aggregateProbeError returned nil; always expect a non-nil error when all probes fail")
			}
			gotAuth := errors.Is(err, transport.ErrAuthFailed)
			gotUnrch := errors.Is(err, transport.ErrUnreachable)

			if gotAuth != tc.wantAuth {
				t.Errorf("ErrAuthFailed: got %v, want %v (err=%v)", gotAuth, tc.wantAuth, err)
			}
			if gotUnrch != tc.wantUnrch {
				t.Errorf("ErrUnreachable: got %v, want %v (err=%v)", gotUnrch, tc.wantUnrch, err)
			}
		})
	}
}
