package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/setup"
)

// newInitCmd builds the setup verb.
//
// Setup is split in two by privilege, and that split is structural rather than
// a matter of taste. A privileged run must not create files in a home
// directory: the home directory it would find belongs to root, so an identity
// key made there is one the daemon — which runs as you — will never see. It
// would then make a different one, and every connection would be refused for
// reasons pointing nowhere near here.
//
// So each run does exactly one half and says who should do the other.
func newInitCmd(a *app) *cobra.Command {
	var (
		assumeYes bool
		noSudo    bool
		undo      bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set this machine up to reach servers by name",
		Long: `Register this machine's resolver so that names ending in your suffix are
answered locally, and set up the pieces that live in your own account.

Run it twice, once each way:

    quic-link init          your own settings, identity and login service
    sudo quic-link init     the one system file that makes names resolve

Either order, any number of times. Each run reports what it will do before it
does anything, and does only what is still missing.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			n, err := a.cfg.Naming()
			if err != nil {
				// A suffix that would take over a namespace must never reach a
				// resolver, so nothing is written and nothing is even planned.
				return err
			}
			_, privileged := setup.RealUser()
			if undo {
				return runUndo(cmd, a, n, privileged)
			}
			return runInit(cmd, a, n, privileged, assumeYes, noSudo)
		},
	}

	cmd.Flags().BoolVar(&assumeYes, "yes", false, "do not ask for confirmation")
	cmd.Flags().BoolVar(&noSudo, "no-sudo", false, "only do the parts that need no privileges")
	cmd.Flags().BoolVar(&undo, "undo", false, "remove what a previous run installed")
	return cmd
}

func runInit(cmd *cobra.Command, a *app, n config.Naming, privileged, assumeYes, noSudo bool) error {
	out := cmd.OutOrStdout()

	if privileged {
		if noSudo {
			return usageErrorf("--no-sudo asks for the unprivileged half, so run it without sudo")
		}
		return runRootHalf(cmd, a, n, assumeYes)
	}
	return runUserHalf(cmd, a, n, assumeYes, noSudo, out)
}

// runRootHalf writes the one system file, and touches nothing else.
func runRootHalf(cmd *cobra.Command, a *app, n config.Naming, assumeYes bool) error {
	out := cmd.OutOrStdout()
	res := setup.DetectResolver(cmd.Context())

	if res.Support == setup.Unsupported {
		fmt.Fprintf(out, "Names cannot be registered on this machine.\n\n  %s\n\n%s\n",
			wrap(res.Reason, 72, "  "), res.Manual)
		fmt.Fprintf(out, "\nNothing was written. Everything else works as it did.\n")
		return nil
	}

	arts := setup.Survey(setup.Inventory(n.Suffix, n.DNSPort, ""))
	missing := setup.Missing(arts)
	if len(missing) == 0 {
		fmt.Fprintf(out, "Already set up. Nothing to do.\n\n%s", setup.DescribeInventory(arts))
		return nil
	}

	fmt.Fprintf(out, "This will:\n")
	for _, m := range missing {
		fmt.Fprintf(out, "  • %s\n      write %s\n", m.Purpose, m.Path)
	}
	if res.Support == setup.SystemdStub {
		fmt.Fprintf(out, "  • reload the resolver so the change takes effect\n"+
			"      this interrupts name lookups on this machine for a moment\n")
	}
	fmt.Fprintf(out, "\nNothing else is installed. Undo with: sudo quic-link init --undo\n")

	ok, err := confirm(cmd, assumeYes, "Proceed?")
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(out, "Nothing was written. Names will not resolve until this is run.\n")
		return nil
	}

	changed := false
	for _, m := range missing {
		r, err := setup.Write(m.Path, m.Content, 0o644)
		if err != nil {
			return err
		}
		if r != setup.Unchanged {
			changed = true
		}
		fmt.Fprintf(out, "  wrote %s\n", m.Path)
	}

	if changed && res.Support == setup.SystemdStub {
		if err := reloadResolver(cmd.Context()); err != nil {
			fmt.Fprintf(out, "\n  The file is in place, but the resolver did not reload: %v\n"+
				"  Reload it yourself, or restart, and names will work.\n", err)
			return nil
		}
		fmt.Fprintf(out, "  reloaded the resolver\n")
	}

	fmt.Fprintf(out, "\nNames ending in %s are now answered by this machine.\n", n.Suffix)
	fmt.Fprintf(out, "Check it with: quic-link doctor\n")
	return nil
}

// runUserHalf sets up what lives in your own account.
func runUserHalf(cmd *cobra.Command, a *app, n config.Naming, assumeYes, noSudo bool, out io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("setup: cannot find your home directory: %w", err)
	}

	keyFile := expandTilde(a.cfg.Identity.KeyFile)
	cfgFile := filepath.Join(home, ".config", "quic-link", "config.toml")
	user := setup.Survey(setup.UserPaths(home, keyFile, cfgFile))

	fmt.Fprintf(out, "Your own settings:\n\n%s\n", setup.DescribeInventory(user))

	if !noSudo {
		root := setup.Survey(setup.Inventory(n.Suffix, n.DNSPort, ""))
		if len(setup.Missing(root)) > 0 {
			fmt.Fprintf(out, "Names will not resolve until one system file is written.\n"+
				"That part needs a password, and is the only part that does:\n\n"+
				"    sudo quic-link init\n\n")
		} else {
			fmt.Fprintf(out, "Names are already registered with this machine's resolver.\n\n")
		}
	}

	fmt.Fprintf(out, "Check everything with: quic-link doctor\n")
	return nil
}

func runUndo(cmd *cobra.Command, a *app, n config.Naming, privileged bool) error {
	out := cmd.OutOrStdout()
	if !privileged {
		fmt.Fprintf(out, "The file to remove belongs to the system, so this needs a password:\n\n"+
			"    sudo quic-link init --undo\n")
		return nil
	}

	arts := setup.Survey(setup.Inventory(n.Suffix, n.DNSPort, ""))
	removedAny := false
	for _, art := range arts {
		removed, err := setup.Remove(art.Path)
		if err != nil {
			// A file that is not ours is left exactly where it is, and named.
			fmt.Fprintf(out, "  left alone: %v\n", err)
			continue
		}
		if removed {
			removedAny = true
			fmt.Fprintf(out, "  removed %s\n", art.Path)
		}
	}
	if !removedAny {
		fmt.Fprintf(out, "Nothing of ours was installed. Nothing to remove.\n")
		return nil
	}
	if runtime.GOOS != "darwin" {
		if err := reloadResolver(cmd.Context()); err == nil {
			fmt.Fprintf(out, "  reloaded the resolver\n")
		}
	}
	fmt.Fprintf(out, "\nNames ending in %s are no longer answered by this machine.\n", n.Suffix)
	return nil
}

// reloadResolver asks the system resolver to read its configuration again.
// This is the one thing setup runs that is not quic-link, and it is why the
// setup verb is allowed to start another program at all.
func reloadResolver(ctx context.Context) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, path, "restart", "systemd-resolved").Run()
}

// confirm asks once, and treats anything that is not a person at a terminal as
// a refusal. Writing to the system and reloading its resolver on the strength
// of a stray pipe is not a thing to do.
func confirm(cmd *cobra.Command, assumeYes bool, question string) (bool, error) {
	if assumeYes {
		return true, nil
	}
	in, ok := cmd.InOrStdin().(*os.File)
	if ok {
		// A pipe or a file is not somebody deciding. Asking the operating
		// system what kind of thing this is avoids a dependency for one bit.
		if fi, err := in.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			ok = false
		}
	}
	if !ok {
		fmt.Fprintf(cmd.OutOrStdout(),
			"\nNot running from a terminal, so nothing was written.\n"+
				"Re-run with --yes to go ahead without being asked.\n")
		return false, nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\n%s [y/N] ", question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// wrap reflows text so a long explanation reads as a paragraph.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, w := range words {
		if col > 0 && col+1+len(w) > width {
			b.WriteString("\n" + indent)
			col = 0
		} else if i > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}
