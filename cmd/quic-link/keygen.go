package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var (
		out   string
		force bool
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 identity key and print its pin",
		Long: `Generate an Ed25519 identity key (PKCS#8 PEM, mode 0600) and write a
creation-time sidecar at <key>.meta. The last line printed is always:

    pin: <base64>

This is the CONTRACT output: exchange that line with the remote end and
supply it as --pin (client) or --authorized-client (agent).

Running keygen again without --force is idempotent: the existing key is
read and its pin is printed without modifying any file. Use --force to
rotate the key; all remote ends must re-pair with the new pin.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return keygenRun(out, force)
		},
	}

	cmd.Flags().StringVar(&out, "out", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	cmd.Flags().BoolVar(&force, "force", false, "rotate: overwrite an existing key (peers must re-pair)")

	return cmd
}

// runKeygen parses args using a stdlib flag.FlagSet and delegates to
// keygenRun.  The flag.FlagSet form is preserved so that tests can call
// runKeygen([]string{"--out", path}) directly without going through cobra.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", defaultKeyPath(), "path to the Ed25519 identity key (PKCS#8 PEM)")
	force := fs.Bool("force", false, "rotate: overwrite an existing key (peers must re-pair)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: quic-link keygen [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	return keygenRun(*out, *force)
}

// keygenRun is the implementation shared by the cobra RunE and the test-facing
// runKeygen wrapper.  It creates or prints the Ed25519 identity key.
func keygenRun(out string, force bool) error {
	keyPath := expandTilde(out)

	_, statErr := os.Stat(keyPath)
	exists := statErr == nil

	if exists && !force {
		// Idempotent path: print the existing pin, rewrite nothing.
		// A missing .meta sidecar is intentionally left alone — do not
		// fabricate a creation time.
		key, err := identity.LoadKey(keyPath)
		if err != nil {
			return fmt.Errorf("load existing key %s: %w", keyPath, err)
		}
		pin, err := identity.PinForKey(key)
		if err != nil {
			return err
		}
		fmt.Printf("pin: %s\n", pin)
		return nil
	}

	if exists && force {
		fmt.Fprintln(os.Stderr, "warning: rotating identity; peers must re-pair with the new pin")
	}

	key, err := identity.Generate()
	if err != nil {
		return err
	}
	if err := identity.WriteKey(keyPath, key); err != nil {
		return fmt.Errorf("write key %s: %w", keyPath, err)
	}
	if err := identity.WriteMeta(keyPath, time.Now().UTC()); err != nil {
		return fmt.Errorf("write key metadata: %w", err)
	}
	pin, err := identity.PinForKey(key)
	if err != nil {
		return err
	}
	fmt.Printf("pin: %s\n", pin)
	return nil
}
