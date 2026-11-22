package pairstate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/mauriciomem/quic-link/internal/atomicfile"
	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/identity"
)

// PairedServer is one [servers.NAME] table of paired.toml: a server this
// client paired with, its address, its pin and when the pairing happened.
type PairedServer struct {
	Addr     string    `toml:"addr"`
	Pin      string    `toml:"pin"`
	PairedAt time.Time `toml:"paired_at"`
}

// pairedFile is the whole of paired.toml.
type pairedFile struct {
	Servers map[string]PairedServer `toml:"servers"`
}

// LoadPaired reads paired.toml. A missing file is an empty, non-nil map.
// Unknown keys are ignored so a file written by a newer version still loads
// (they are dropped if this version rewrites the file). Bad TOML or an
// invalid server is a *MalformedError with Line 0, and no servers.
//
// paired.toml is written only by the client's own pairing verbs, run by one
// operator at a time, so unlike authorized_clients it takes no lock. Its
// directory and the file itself must be private to the current user (see
// checkPrivate), otherwise the error matches ErrUnsafePath; UpsertPaired and
// ForgetPaired read through LoadPaired and are refused the same way.
func LoadPaired(path string) (map[string]PairedServer, error) {
	exists, err := verifyStatePath(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return map[string]PairedServer{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]PairedServer{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pairstate: read %s: %w", path, err)
	}
	var f pairedFile
	if err := toml.NewDecoder(bytes.NewReader(data)).Decode(&f); err != nil {
		return nil, &MalformedError{Path: path, Reason: fmt.Sprintf("invalid TOML: %v", err)}
	}
	servers := make(map[string]PairedServer, len(f.Servers))
	for name, s := range f.Servers {
		if err := validatePaired(name, s.Addr, s.Pin); err != nil {
			return nil, &MalformedError{Path: path, Reason: err.Error()}
		}
		servers[name] = s
	}
	return servers, nil
}

// UpsertPaired records server name at addr with pin, paired at now, replacing
// any earlier record of the same name and keeping the others. The file is
// written atomically, mode 0600, its directory 0700. Invalid input or an
// existing malformed file is an error and leaves the file untouched.
func UpsertPaired(path, name, addr, pin string, now time.Time) error {
	return upsertPairedWith(defaultPairedOpts(), path, name, addr, pin, now)
}

// pairedOpts are the paired.toml writer's injectable dependencies.
type pairedOpts struct {
	write func(path string, data []byte, perm os.FileMode) error
}

// defaultPairedOpts returns the production dependencies.
func defaultPairedOpts() pairedOpts { return pairedOpts{write: atomicfile.Write} }

// upsertPairedWith is UpsertPaired with injectable dependencies.
func upsertPairedWith(o pairedOpts, path, name, addr, pin string, now time.Time) error {
	if err := validatePaired(name, addr, pin); err != nil {
		return fmt.Errorf("pairstate: %w", err)
	}
	servers, err := LoadPaired(path)
	if err != nil {
		return err
	}
	servers[name] = PairedServer{Addr: addr, Pin: pin, PairedAt: now}
	return writePairedWith(o, path, servers)
}

// ForgetPaired removes server name. An unknown name, or a missing file, is
// ErrNotFound and leaves the file untouched.
func ForgetPaired(path, name string) error {
	servers, err := LoadPaired(path)
	if err != nil {
		return err
	}
	if _, ok := servers[name]; !ok {
		return fmt.Errorf("pairstate: server %q is not in %s: %w", name, path, ErrNotFound)
	}
	delete(servers, name)
	return writePairedWith(defaultPairedOpts(), path, servers)
}

// writePairedWith replaces paired.toml with servers.
func writePairedWith(o pairedOpts, path string, servers map[string]PairedServer) error {
	data, err := toml.Marshal(pairedFile{Servers: servers})
	if err != nil {
		return fmt.Errorf("pairstate: encode %s: %w", path, err)
	}
	if err := o.write(path, data, 0o600); err != nil {
		return fmt.Errorf("pairstate: write %s: %w", path, err)
	}
	return nil
}

// validatePaired checks one server record the way config checks a server:
// the name is a hostname label (config.ValidateServerName), the addr is a
// host:port with a host (config.DialableAddr) and the pin is canonical. The
// name and the addr are first limited to bytes 0x21-0x7E, so every error
// text, including config's, is printable ASCII.
func validatePaired(name, addr, pin string) error {
	if !visibleASCII(name) {
		return fmt.Errorf("server name %+q cannot be part of a hostname", name)
	}
	if err := config.ValidateServerName(name); err != nil {
		return err
	}
	if addr == "" {
		return fmt.Errorf("server %q: addr is empty", name)
	}
	if !visibleASCII(addr) {
		return fmt.Errorf("server %q: addr %+q contains a space, control or non-ASCII character", name, addr)
	}
	if err := config.DialableAddr(name, addr); err != nil {
		return err
	}
	if _, err := identity.ParsePinStrict(pin); err != nil {
		return fmt.Errorf("server %q: invalid pin %q: %w", name, pin, err)
	}
	return nil
}

// visibleASCII reports whether every byte of s is in 0x21-0x7E.
func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
