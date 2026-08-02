package daemon_test

import (
	"context"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// A disabled server still appears in the status snapshot, and the direction it
// reports must be the direction its config actually asks for. Reporting "dial"
// for a server configured to listen is a small lie, but status output exists to
// be trusted, and a reader debugging a reverse-mode config is precisely the
// person a wrong direction would mislead.

// disabledPoolState builds a pool holding exactly one disabled server and
// returns its state. The transport factory is never called: the only server is
// disabled, so no dialing happens.
func disabledPoolState(t *testing.T, srv config.Server) daemon.SessionState {
	t.Helper()

	disabled := false
	srv.Enabled = &disabled

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"off": srv}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx,
		cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			t.Error("transport factory called for a disabled server")
			return nil, nil
		},
		daemon.DefaultReconnectPolicy(),
		newFixedClock(),
		nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	states := pool.State()
	if len(states) != 1 {
		t.Fatalf("State() returned %d entries, want 1", len(states))
	}
	return states[0]
}

// TestDisabledEntry_ReportsConfiguredTransport covers both directions.
//
// Pre-fix failure mode: disabledEntry.State() hardcoded Transport: "dial", so
// the reverse-mode row reported "dial" for a server configured with listen.
// The forward row passed before and after, which is why it is kept: it proves
// the fix did not simply invert the lie.
func TestDisabledEntry_ReportsConfiguredTransport(t *testing.T) {
	tests := []struct {
		name string
		srv  config.Server
		want string
	}{
		{
			name: "disabled forward-mode server reports dial",
			srv:  config.Server{Addr: "127.0.0.1:19990"},
			want: "dial",
		},
		{
			name: "disabled reverse-mode server reports listen",
			srv:  config.Server{Listen: ":19991"},
			want: "listen",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disabledPoolState(t, tt.srv)
			if got.State != "disabled" {
				t.Errorf("State = %q, want disabled", got.State)
			}
			if got.Transport != tt.want {
				t.Errorf("Transport = %q, want %q", got.Transport, tt.want)
			}
		})
	}
}
