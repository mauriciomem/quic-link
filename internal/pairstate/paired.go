package pairstate

import "time"

// PairedServer is one [servers.NAME] table of paired.toml.
type PairedServer struct {
	Addr     string    `toml:"addr"`
	Pin      string    `toml:"pin"`
	PairedAt time.Time `toml:"paired_at"`
}

func LoadPaired(path string) (map[string]PairedServer, error) { return nil, errNotImplemented }

func UpsertPaired(path, name, addr, pin string, now time.Time) error { return errNotImplemented }

func ForgetPaired(path, name string) error { return errNotImplemented }
