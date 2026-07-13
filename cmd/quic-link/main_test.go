package main

import (
	"testing"

	"github.com/mauriciomem/quic-link/internal/proto"
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
