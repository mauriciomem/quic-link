package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/ipc"
)

// errDockerNotReady is returned when docker-env's zero-port rule fires: the
// named server's docker port is 0, or its session is not "connected". Exit 3
// is what keeps "eval $(quic-link docker-env)" a safe no-op instead of
// exporting DOCKER_HOST to a port nothing is listening on and silently
// breaking every later docker call.
type errDockerNotReady struct {
	server string
	reason string
}

func (e *errDockerNotReady) Error() string {
	return fmt.Sprintf("docker not reachable for server %q: %s", e.server, e.reason)
}

// alreadyReported signals that the human-readable reason was already written
// to stderr by runDockerEnv, so main() must not print an additional
// slog.Error line.
func (e *errDockerNotReady) alreadyReported() bool { return true }

func newDockerEnvCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docker-env [SERVER]",
		Short: "Print an eval-able DOCKER_HOST export for a connected server's docker port",
		Long: `Read the docker local port from the daemon's live status snapshot — never
recomputed from config, since the daemon may bind a different port than
config requests — and print (CONTRACT):

  export DOCKER_HOST=tcp://127.0.0.1:<docker_local_port>

If the docker port is 0, or the server is not connected, nothing is printed
to stdout, a human message goes to stderr, and the exit code is 3. This
keeps "eval $(quic-link docker-env)" a safe no-op instead of setting
DOCKER_HOST to a port nothing is listening on.

With no SERVER, the sole known server in the config is used automatically
(error 2 if the config has more than one).`,
		Args: wrapArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDockerEnv(cmd, a, args)
		},
	}
	return cmd
}

func runDockerEnv(cmd *cobra.Command, a *app, args []string) error {
	serverName, err := autoSelectServer(a, args)
	if err != nil {
		return err
	}
	// A name that is not known at all is a usage mistake (exit 2), not a
	// docker-readiness condition (exit 3). This must run before the daemon
	// is ever asked for status: errDockerNotReady is matched ahead of
	// errUsage in exitCodeForError, so once that error exists it can no
	// longer be remapped to 2 by wrapping it — the fix has to keep it from
	// being constructed in the first place.
	if err := requireKnownServer(a, serverName); err != nil {
		return err
	}

	sock, err := daemonSocketPath(a.cfg)
	if err != nil {
		return fmt.Errorf("resolve socket path: %w", err)
	}

	raw, err := ipc.NewClient(sock).StatusJSON()
	if err != nil {
		return relayIPCError(cmd, "status", err, relayCannotReturnRoutesError)
	}

	var snap daemon.StatusSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("parse daemon status: %w", err)
	}

	var found *daemon.ServerSnapshot
	for i := range snap.Servers {
		if snap.Servers[i].Name == serverName {
			found = &snap.Servers[i]
			break
		}
	}

	switch {
	case found == nil:
		fmt.Fprintf(cmd.ErrOrStderr(),
			"server %q is not managed by the running daemon\n", serverName)
		return &errDockerNotReady{server: serverName, reason: "not managed by the running daemon"}
	case found.Session == "disabled":
		// A disabled server is a distinct, more specific reason than the
		// generic "not connected" below: the operator turned the server off
		// in config, and telling them exactly that (with the remedy) is
		// clearer than the generic "session=disabled" reading, which forces
		// the reader to already know what the session enum values mean.
		// Matches ssh's and stdio's message for the identical config state.
		fmt.Fprintf(cmd.ErrOrStderr(),
			"server %q is disabled; set enabled = true in the config to use it\n", serverName)
		return &errDockerNotReady{server: serverName, reason: "disabled"}
	case found.Session != "connected":
		fmt.Fprintf(cmd.ErrOrStderr(),
			"server %q is not connected (session=%s); docker is not reachable\n",
			serverName, found.Session)
		return &errDockerNotReady{server: serverName, reason: fmt.Sprintf("session=%s", found.Session)}
	case found.LocalPorts.Docker == 0:
		fmt.Fprintf(cmd.ErrOrStderr(),
			"server %q has no docker port bound; docker is not reachable\n", serverName)
		return &errDockerNotReady{server: serverName, reason: "docker port is 0"}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "export DOCKER_HOST=tcp://127.0.0.1:%d\n", found.LocalPorts.Docker)
	return nil
}
