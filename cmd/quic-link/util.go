package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
)

// errUsage marks an error as a usage/validation failure so main() exits with
// the usage-error exit code (2).
var errUsage = errors.New("usage error")

// usageErrorf creates an error that wraps errUsage, signalling a
// command-line validation failure (wrong flags, missing arguments, etc.).
func usageErrorf(format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), errUsage)
}

// defaultKeyPath resolves ~/.config/quic-link/key.pem on every OS.
// os.UserHomeDir is used rather than os.UserConfigDir because on macOS
// UserConfigDir returns ~/Library/Application Support, whereas the project
// follows the same ~/.config scheme on every platform.
func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "key.pem"
	}
	return filepath.Join(home, ".config", "quic-link", "key.pem")
}

// expandTilde expands a leading ~ or ~/ to the user's home directory.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// pinList collects repeatable --authorized-client flags.  Each value is
// validated and canonicalised via identity.ParsePin as it is set, so a
// bad pin is rejected immediately rather than at connection time.
type pinList []string

func (p *pinList) String() string { return strings.Join(*p, ",") }

func (p *pinList) Set(v string) error {
	norm, err := identity.ParsePin(v)
	if err != nil {
		return err
	}
	*p = append(*p, norm)
	return nil
}

// Type returns the pflag value type name, satisfying the pflag.Value interface
// (cobra uses pflag, which requires this method in addition to String/Set).
func (p *pinList) Type() string { return "pin" }

// clientTLSFromFlags loads the Ed25519 identity key and builds the client-side
// pinning tls.Config for the expected server pin.  Shared by connect and ping.
func clientTLSFromFlags(keyFile, serverPin string) (*tls.Config, error) {
	key, err := identity.LoadKey(expandTilde(keyFile))
	if err != nil {
		return nil, fmt.Errorf("load identity key: %w", err)
	}
	tlsConf, err := identity.ClientTLS(key, serverPin)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}
	return tlsConf, nil
}

// readKeyCreatedRFC3339 returns the key's creation time formatted as RFC3339
// UTC, or an empty string if the .meta sidecar is absent or cannot be read.
// Errors are silently swallowed — advertising the key age is best-effort only.
func readKeyCreatedRFC3339(keyFile string) string {
	created, present, err := identity.ReadMeta(keyFile)
	if err != nil || !present {
		return ""
	}
	return created.UTC().Format(time.RFC3339)
}
