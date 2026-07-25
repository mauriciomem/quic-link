package main

import (
	"fmt"
	"testing"

	"github.com/mauriciomem/quic-link/internal/proto"
	"github.com/mauriciomem/quic-link/internal/transport"
)

func TestExitCodeForStatus(t *testing.T) {
	cases := []struct {
		status proto.Status
		want   int
	}{
		{proto.StatusOK, 0},
		{proto.StatusUnknownTarget, 5},
		{proto.StatusUnauthorized, 4},
		{proto.StatusDialFailed, 5},
		{proto.StatusDraining, 5},
		{proto.StatusBadHeader, 1},
		{proto.StatusUnsupportedVersion, 1},
	}
	for _, tc := range cases {
		if got := exitCodeForStatus(tc.status); got != tc.want {
			t.Errorf("exitCodeForStatus(%v) = %d, want %d", tc.status, got, tc.want)
		}
	}
}

// TestExitCodeForError_TransportSentinels verifies that the two transport-layer
// sentinels map to their specified exit codes via the single exitCodeForError
// site. Both bare sentinels and wrapped versions must be recognised so that
// errors wrapped with %w by classifyDialError or intermediate callers still hit
// the correct branch.
func TestExitCodeForError_TransportSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		// Bare sentinels.
		{"ErrUnreachable bare", transport.ErrUnreachable, 3},
		{"ErrAuthFailed bare", transport.ErrAuthFailed, 4},
		// Wrapped — mirrors what classifyDialError produces.
		{"ErrUnreachable wrapped",
			fmt.Errorf("outer: %w: inner detail", transport.ErrUnreachable), 3},
		{"ErrAuthFailed wrapped",
			fmt.Errorf("%w (extra context)", transport.ErrAuthFailed), 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := exitCodeForError(tc.err)
			if got != tc.want {
				t.Errorf("exitCodeForError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
