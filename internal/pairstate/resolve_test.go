/**
 * @spec-handoff
 * @interface EffectiveAuthorized(cfgList, flagList []string, fileEntries []Entry) map[string]struct{}
 * @interface ResolveServers(cfg map[string]config.Server, paired map[string]PairedServer) (map[string]config.Server, error)  // no flag input
 * @behavior
 *   - EffectiveAuthorized: a non-empty flag list replaces both the config list and the file; otherwise config list union file entries of every state
 *   - ResolveServers: paired-only server -> config.Server{Addr, Pin}; config-only servers pass through unchanged
 *   - Server in both: config Addr wins over the paired addr; same pin -> config server kept as is
 *   - Different pins -> error matching ErrPinConflict and config.ErrInvalid naming the server, paired.toml and "server forget NAME"
 *   - Returns a new map; inputs are never mutated
 * @see ./resolve.go
 */

package pairstate

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

func set(pins ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		m[p] = struct{}{}
	}
	return m
}

func TestEffectiveAuthorized_FlagsReplaceConfigAndFile(t *testing.T) {
	c1, c2, f1, f2, f3, fl := testPin("eff-c1"), testPin("eff-c2"), testPin("eff-f1"), testPin("eff-f2"), testPin("eff-f3"), testPin("eff-flag")
	file := []Entry{
		{Pin: f1, State: StateConfirmed},
		{Pin: f2, State: StateUnconfirmed},
		{Pin: f3, State: StateUnknown},
	}
	cases := []struct {
		name  string
		cfg   []string
		flags []string
		file  []Entry
		want  map[string]struct{}
	}{
		{"config and file union, every state", []string{c1, c2}, nil, file, set(c1, c2, f1, f2, f3)},
		{"empty flag list is no flag", []string{c1}, []string{}, file, set(c1, f1, f2, f3)},
		{"file only", nil, nil, file, set(f1, f2, f3)},
		{"config only", []string{c1}, nil, nil, set(c1)},
		{"flags replace config and file", []string{c1, c2}, []string{fl}, file, set(fl)},
		{"flag repeating a file pin keeps only flags", []string{c1}, []string{f1, fl}, file, set(f1, fl)},
		{"overlap is deduplicated", []string{f1}, nil, file, set(f1, f2, f3)},
		{"nothing", nil, nil, nil, set()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveAuthorized(tc.cfg, tc.flags, tc.file)
			if got == nil || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("EffectiveAuthorized = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveServers_Rules(t *testing.T) {
	pHome, pOffice, pCfg, pOther := testPin("rs-home"), testPin("rs-office"), testPin("rs-cfg"), testPin("rs-other")
	off := false

	t.Run("paired-only, config-only and override", func(t *testing.T) {
		cfg := map[string]config.Server{
			"cfg-only": {Addr: "c:1", Pin: pCfg, Enabled: &off, LocalPorts: map[string]int{"web": 8080}},
			"office":   {Addr: "office.internal:4433", Pin: pOffice},
		}
		paired := map[string]PairedServer{
			"home":   {Addr: "h:1", Pin: pHome, PairedAt: clockT1},
			"office": {Addr: "o-paired:1", Pin: pOffice, PairedAt: clockT1},
		}
		cfgCopy := map[string]config.Server{
			"cfg-only": {Addr: "c:1", Pin: pCfg, Enabled: &off, LocalPorts: map[string]int{"web": 8080}},
			"office":   {Addr: "office.internal:4433", Pin: pOffice},
		}
		pairedCopy := map[string]PairedServer{
			"home":   {Addr: "h:1", Pin: pHome, PairedAt: clockT1},
			"office": {Addr: "o-paired:1", Pin: pOffice, PairedAt: clockT1},
		}

		got, err := ResolveServers(cfg, paired)
		if err != nil {
			t.Fatalf("ResolveServers: %v", err)
		}
		want := map[string]config.Server{
			"cfg-only": {Addr: "c:1", Pin: pCfg, Enabled: &off, LocalPorts: map[string]int{"web": 8080}},
			"office":   {Addr: "office.internal:4433", Pin: pOffice},
			"home":     {Addr: "h:1", Pin: pHome},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ResolveServers = %+v\nwant %+v", got, want)
		}

		if got != nil {
			got["home"] = config.Server{Addr: "mutated"}
			delete(got, "cfg-only")
		}
		if !reflect.DeepEqual(cfg, cfgCopy) {
			t.Errorf("config input mutated: %+v", cfg)
		}
		if !reflect.DeepEqual(paired, pairedCopy) {
			t.Errorf("paired input mutated: %+v", paired)
		}
	})

	t.Run("pin conflict names both sources and the fix", func(t *testing.T) {
		cfg := map[string]config.Server{"home": {Addr: "h:1", Pin: pOther}}
		paired := map[string]PairedServer{"home": {Addr: "h:1", Pin: pHome, PairedAt: clockT1}}
		got, err := ResolveServers(cfg, paired)
		if !errors.Is(err, ErrPinConflict) || !errors.Is(err, config.ErrInvalid) {
			t.Fatalf("err = %v, want ErrPinConflict and config.ErrInvalid", err)
		}
		msg := err.Error()
		for _, part := range []string{"home", "paired.toml", "config", "server forget home"} {
			if !strings.Contains(msg, part) {
				t.Errorf("error %q does not mention %q", msg, part)
			}
		}
		if got != nil {
			t.Errorf("conflict returned servers %+v", got)
		}
	})

	t.Run("empty inputs", func(t *testing.T) {
		got, err := ResolveServers(nil, nil)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("ResolveServers(nil, nil) = (%#v, %v), want empty non-nil map", got, err)
		}
	})
}
