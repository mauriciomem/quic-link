package main

import (
	"github.com/spf13/cobra"
)

// newAttachCmd returns the attach command: pure sugar for
// "ssh SERVER -- -t tmux attach -t SESSION". It calls runSSHCore directly
// (the same function the ssh verb itself calls) rather than reimplementing
// any part of the ssh invocation, so there is zero duplicated
// ProxyCommand-construction or ssh-exec logic in this file. Its exit code is
// therefore ssh's own too, exactly like ssh.
func newAttachCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach SERVER SESSION",
		Short: "Attach to a tmux session on SERVER",
		Long: `Sugar for:

  quic-link ssh SERVER -- -t tmux attach -t SESSION

Delegates entirely to the ssh verb's own implementation (runSSHCore) — no
ssh-invocation logic is duplicated here. Its exit code is therefore ssh's
own, exactly like ssh itself.`,
		Args: wrapArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, session := args[0], args[1]
			passthrough := []string{"-t", "tmux", "attach", "-t", session}
			return runSSHCore(cmd, a, server, passthrough, false, "", "")
		},
	}
	return cmd
}
