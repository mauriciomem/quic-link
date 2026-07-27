package main

import (
	"errors"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// TestExitCodeMapping_DaemonErrors verifies that the single exitCodeForError
// site maps the new IPC error sentinels to exit 3, and that the "owner already
// running" typed error also maps to exit 3.
func TestExitCodeMapping_DaemonErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{
			name:     "ErrDaemonAbsent maps to 3",
			err:      ipc.ErrDaemonAbsent,
			wantCode: 3,
		},
		{
			name:     "ErrDaemonAbsent wrapped maps to 3",
			err:      errors.Join(ipc.ErrDaemonAbsent, errors.New("context")),
			wantCode: 3,
		},
		{
			name:     "ErrSchemaMismatch maps to 3",
			err:      ipc.ErrSchemaMismatch,
			wantCode: 3,
		},
		{
			name:     "ErrSchemaMismatch wrapped maps to 3",
			err:      errors.Join(ipc.ErrSchemaMismatch, errors.New("wrapped")),
			wantCode: 3,
		},
		{
			name:     "errOwnerRunning maps to 3",
			err:      &errOwnerRunningType{sock: "/tmp/test.sock"},
			wantCode: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCodeForError(tt.err)
			if got != tt.wantCode {
				t.Errorf("exitCodeForError(%v) = %d, want %d", tt.err, got, tt.wantCode)
			}
		})
	}
}
