/**
 * @spec-handoff
 * @interface AuthorizedClientsPath() (string, error); PairedPath() (string, error)
 * @interface ValidateDistinctListenPins(servers map[string]Server) error  // exported form of validateDistinctListenPins; (*Config).Validate keeps calling it
 * @behavior
 *   - The path helpers return $HOME/.config/quic-link/{authorized_clients,paired.toml} (os.UserHomeDir, no XDG)
 *   - Unknown home ($HOME empty or unset) -> ("", error); a relative home -> ("", error): never a relative path, unlike the key/config defaults
 *   - ValidateDistinctListenPins: two enabled waiting servers (listen set, addr empty) sharing a pin -> error matching ErrInvalid naming "servers.A and servers.B" (sorted order, first pair); dialing, disabled and listen+addr servers are skipped
 * @see ./config.go
 */

package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

func TestStatePaths_Defaults(t *testing.T) {
	helpers := []struct {
		name string
		fn   func() (string, error)
		file string
	}{
		{"AuthorizedClientsPath", config.AuthorizedClientsPath, "authorized_clients"},
		{"PairedPath", config.PairedPath, "paired.toml"},
	}
	for _, h := range helpers {
		t.Run(h.name+": under the home directory", func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			got, err := h.fn()
			if want := filepath.Join(home, ".config", "quic-link", h.file); err != nil || got != want {
				t.Errorf("%s() = (%q, %v), want (%q, nil)", h.name, got, err, want)
			}
		})
		for _, tc := range []struct {
			name string
			set  func(t *testing.T)
		}{
			{"HOME empty", func(t *testing.T) { t.Setenv("HOME", "") }},
			{"HOME unset", func(t *testing.T) {
				t.Setenv("HOME", "")
				if err := os.Unsetenv("HOME"); err != nil {
					t.Fatal(err)
				}
			}},
			{"HOME relative", func(t *testing.T) { t.Setenv("HOME", "relative/home") }},
		} {
			t.Run(h.name+": "+tc.name+" is an error, never a relative path", func(t *testing.T) {
				tc.set(t)
				got, err := h.fn()
				if err == nil {
					t.Errorf("%s() = (%q, nil), want an error", h.name, got)
				}
				if got != "" {
					t.Errorf("%s() returned path %q with its error, want \"\"", h.name, got)
				}
			})
		}
	}
}

func TestValidateDistinctListenPins_Exported(t *testing.T) {
	pin, other := reversePin(t), reversePin(t)
	off, on := false, true
	cases := []struct {
		name    string
		servers map[string]config.Server
		pair    string // "" = accepted; else "servers.X and servers.Y"
	}{
		{"two waiting servers share a pin", map[string]config.Server{
			"alpha": {Listen: ":7443", Pin: pin},
			"beta":  {Listen: ":7444", Pin: pin},
		}, "servers.alpha and servers.beta"},
		{"explicitly enabled waiting servers share a pin", map[string]config.Server{
			"alpha": {Listen: ":7443", Pin: pin, Enabled: &on},
			"beta":  {Listen: ":7444", Pin: pin, Enabled: &on},
		}, "servers.alpha and servers.beta"},
		{"distinct pins", map[string]config.Server{
			"alpha": {Listen: ":7443", Pin: pin},
			"beta":  {Listen: ":7444", Pin: other},
		}, ""},
		{"dialing servers share a pin", map[string]config.Server{
			"alpha": {Addr: "127.0.0.1:7443", Pin: pin},
			"beta":  {Addr: "127.0.0.1:7444", Pin: pin},
		}, ""},
		{"waiting and dialing share a pin", map[string]config.Server{
			"alpha": {Listen: ":7443", Pin: pin},
			"beta":  {Addr: "127.0.0.1:7444", Pin: pin},
		}, ""},
		{"listen with addr is not waiting", map[string]config.Server{
			"alpha": {Listen: ":7443", Pin: pin},
			"beta":  {Listen: ":7444", Addr: "127.0.0.1:7444", Pin: pin},
		}, ""},
		{"disabled waiting server is skipped", map[string]config.Server{
			"alpha": {Listen: ":7443", Pin: pin},
			"beta":  {Listen: ":7444", Pin: pin, Enabled: &off},
		}, ""},
		{"empty", map[string]config.Server{}, ""},
		{"nil", nil, ""},
	}
	// 26 waiting servers a..z with distinct pins except m and q: the sorted
	// walk must report exactly that pair, every time.
	many := map[string]config.Server{}
	for c := 'a'; c <= 'z'; c++ {
		many[string(c)] = config.Server{Listen: fmt.Sprintf(":%d", 7000+int(c)), Pin: reversePin(t)}
	}
	q := many["q"]
	q.Pin = many["m"].Pin
	many["q"] = q
	cases = append(cases, struct {
		name    string
		servers map[string]config.Server
		pair    string
	}{"26 servers, one shared pair", many, "servers.m and servers.q"})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				err := config.ValidateDistinctListenPins(tc.servers)
				if tc.pair == "" {
					if err != nil {
						t.Fatalf("ValidateDistinctListenPins = %v, want nil", err)
					}
					continue
				}
				if !errors.Is(err, config.ErrInvalid) {
					t.Fatalf("ValidateDistinctListenPins = %v, want ErrInvalid", err)
				}
				if !strings.Contains(err.Error(), tc.pair+" share a pin") {
					t.Fatalf("run %d: error %q, want it to name %q", i, err, tc.pair)
				}
			}
		})
	}
}
