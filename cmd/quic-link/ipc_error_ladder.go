package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// relayIPCError turns a client call's error into the stderr message and the
// error value returned up to main(), for every verb that talks to the daemon
// over the IPC socket. Six call sites across status, vhosts, vhosts rm,
// expose and docker-env used to carry their own copy of this same
// three-condition check; a sixth daemon-talking verb now has one obvious
// thing to call instead of a ladder to reproduce correctly by hand.
//
// The three conditions are checked in this fixed order: daemon absent, then
// stale schema, then — when routesAware is true — a *ipc.RoutesError. Fixing
// the order here means no caller has to reason about which one wins if an
// error somehow matched more than one; in practice none of the client
// methods this is called with ever produce an error that could.
//
// routesAware is false for the two call sites whose client method
// (StatusJSON) never returns a *ipc.RoutesError at all — runStatusPlain and
// docker-env's status read both relay ONLY StatusJSON's own two socket-level
// conditions. That is not a gap relative to the other four call sites; it is
// this parameter saying "this call's method cannot produce a RoutesError",
// which is simply true for those two and false nowhere it should be true.
func relayIPCError(cmd *cobra.Command, verb string, err error, routesAware bool) error {
	if errors.Is(err, ipc.ErrDaemonAbsent) {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"daemon is not running; start it with: quic-link daemon")
		return err
	}
	if errors.Is(err, ipc.ErrSchemaMismatch) {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"daemon is a stale version; restart it with: quic-link daemon")
		return err
	}
	if routesAware {
		var re *ipc.RoutesError
		if errors.As(err, &re) {
			// The daemon already chose the exact reason and the status that
			// belongs to it; relaying both unchanged keeps one description of
			// each condition rather than two that can drift apart.
			fmt.Fprintln(cmd.ErrOrStderr(), re.Msg)
			return &errFinalExitCode{code: int(re.Status), msg: re.Msg}
		}
	}
	return fmt.Errorf("%s: %w", verb, err)
}
