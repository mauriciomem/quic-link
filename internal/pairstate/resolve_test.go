/**
 * @spec-handoff
 * @interface EffectiveAuthorized(cfgList, flagList []string, fileEntries []Entry) map[string]struct{}
 * @interface ResolveServers(cfg map[string]config.Server, paired map[string]PairedServer) (map[string]config.Server, error)  // no flag input
 * @behavior
 *   - EffectiveAuthorized: a non-empty flag list replaces both the config list and the file; otherwise config list union file entries of every state
 *   - ResolveServers: paired-only server -> config.Server{Addr, Pin}; config-only servers pass through unchanged
 *   - Server in both: config Addr or Listen wins over the paired addr (paired addr only when both are empty); an empty config pin is filled from paired; same pin -> config server kept as is
 *   - Paired entries are re-validated like paired.toml (name, addr, pin); the first failure -> error matching config.ErrInvalid, nil result
 *   - Conflicts are checked in sorted name order, so the same server is reported on every run
 *   - Different pins -> error matching ErrPinConflict and config.ErrInvalid naming the server, paired.toml and "server forget NAME"
 *   - Returns a new map; inputs are never mutated
 *   - The merged map is checked with config.ValidateDistinctListenPins before returning: two enabled waiting servers sharing a pin after the merge -> error matching config.ErrInvalid naming both, nil result
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

	t.Run("listen-mode config keeps listen", func(t *testing.T) {
		cfg := map[string]config.Server{"x": {Listen: ":4433"}}
		paired := map[string]PairedServer{"x": {Addr: "p:1", Pin: pHome, PairedAt: clockT1}}
		got, err := ResolveServers(cfg, paired)
		if err != nil {
			t.Fatalf("ResolveServers: %v", err)
		}
		if want := (config.Server{Listen: ":4433", Pin: pHome}); !reflect.DeepEqual(got["x"], want) {
			t.Errorf("x = %+v, want %+v (no addr beside listen, pin filled)", got["x"], want)
		}
	})

	t.Run("config with neither addr nor listen takes both", func(t *testing.T) {
		cfg := map[string]config.Server{"x": {}}
		paired := map[string]PairedServer{"x": {Addr: "p:1", Pin: pHome, PairedAt: clockT1}}
		got, err := ResolveServers(cfg, paired)
		if err != nil {
			t.Fatalf("ResolveServers: %v", err)
		}
		if want := (config.Server{Addr: "p:1", Pin: pHome}); !reflect.DeepEqual(got["x"], want) {
			t.Errorf("x = %+v, want %+v", got["x"], want)
		}
	})

	t.Run("empty config pin is filled, not a conflict", func(t *testing.T) {
		cfg := map[string]config.Server{"x": {Addr: "c:1"}}
		paired := map[string]PairedServer{"x": {Addr: "p:1", Pin: pHome, PairedAt: clockT1}}
		got, err := ResolveServers(cfg, paired)
		if err != nil {
			t.Fatalf("ResolveServers = %v, want nil: an empty config pin is not a conflict", err)
		}
		if want := (config.Server{Addr: "c:1", Pin: pHome}); !reflect.DeepEqual(got["x"], want) {
			t.Errorf("x = %+v, want %+v", got["x"], want)
		}
	})

	t.Run("conflicts are reported in name order", func(t *testing.T) {
		a1, b1 := testPin("rs-order-a1"), testPin("rs-order-b1")
		cfg := map[string]config.Server{"a": {Addr: "h:1", Pin: a1}, "b": {Addr: "h:1", Pin: b1}}
		paired := map[string]PairedServer{
			"a": {Addr: "h:1", Pin: pHome, PairedAt: clockT1},
			"b": {Addr: "h:1", Pin: pOffice, PairedAt: clockT1},
		}
		for i := range 20 {
			_, err := ResolveServers(cfg, paired)
			if err == nil {
				t.Fatalf("run %d: ResolveServers = nil, want a conflict", i)
			}
			if msg := err.Error(); !strings.Contains(msg, `server "a"`) || strings.Contains(msg, `server "b"`) {
				t.Fatalf("run %d: error %q, want the conflict for server \"a\" only", i, msg)
			}
		}
	})

	t.Run("paired entries are re-validated", func(t *testing.T) {
		for name, paired := range map[string]map[string]PairedServer{
			"invalid name": {"Home": {Addr: "h:1", Pin: pHome, PairedAt: clockT1}},
			"invalid addr": {"home": {Addr: "h\x1b:1", Pin: pHome, PairedAt: clockT1}},
		} {
			got, err := ResolveServers(nil, paired)
			if !errors.Is(err, config.ErrInvalid) {
				t.Errorf("%s: err = %v, want config.ErrInvalid", name, err)
			}
			if got != nil {
				t.Errorf("%s: returned servers %+v, want nil", name, got)
			}
		}
	})

	t.Run("empty inputs", func(t *testing.T) {
		got, err := ResolveServers(nil, nil)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("ResolveServers(nil, nil) = (%#v, %v), want empty non-nil map", got, err)
		}
	})
}

func TestResolveServers_RejectsSharedListenPinAfterMerge(t *testing.T) {
	shared, other := testPin("merge-shared"), testPin("merge-other")
	off := false
	// alpha waits with no pin of its own; paired.toml fills in beta's pin.
	cfg := map[string]config.Server{
		"alpha": {Listen: "127.0.0.1:7443"},
		"beta":  {Listen: "127.0.0.1:7444", Pin: shared},
	}

	t.Run("paired pin collides with a waiting server", func(t *testing.T) {
		got, err := ResolveServers(cfg, map[string]PairedServer{
			"alpha": {Addr: "a.example.net:4433", Pin: shared, PairedAt: clockT1},
		})
		if !errors.Is(err, config.ErrInvalid) {
			t.Fatalf("ResolveServers = (%v, %v), want an error matching config.ErrInvalid", got, err)
		}
		if got != nil {
			t.Errorf("ResolveServers returned %v with its error, want nil", got)
		}
		if msg := err.Error(); !strings.Contains(msg, "servers.alpha") || !strings.Contains(msg, "servers.beta") {
			t.Errorf("error %q should name both servers", msg)
		}
		if errors.Is(err, ErrPinConflict) {
			t.Errorf("error %v must not be a pin conflict: the sources agree", err)
		}
	})
	t.Run("control: distinct pins resolve", func(t *testing.T) {
		got, err := ResolveServers(cfg, map[string]PairedServer{
			"alpha": {Addr: "a.example.net:4433", Pin: other, PairedAt: clockT1},
		})
		if err != nil || got["alpha"].Pin != other || got["alpha"].Listen != "127.0.0.1:7443" {
			t.Errorf("ResolveServers = (%v, %v), want alpha listening with the paired pin", got, err)
		}
	})
	t.Run("control: a disabled waiting server does not collide", func(t *testing.T) {
		in := map[string]config.Server{
			"alpha": {Listen: "127.0.0.1:7443"},
			"beta":  {Listen: "127.0.0.1:7444", Pin: shared, Enabled: &off},
		}
		if _, err := ResolveServers(in, map[string]PairedServer{
			"alpha": {Addr: "a.example.net:4433", Pin: shared, PairedAt: clockT1},
		}); err != nil {
			t.Errorf("ResolveServers = %v, want nil", err)
		}
	})
	t.Run("control: a paired-only dialing server sharing the pin is fine", func(t *testing.T) {
		if _, err := ResolveServers(cfg, map[string]PairedServer{
			"gamma": {Addr: "g.example.net:4433", Pin: shared, PairedAt: clockT1},
		}); err != nil {
			t.Errorf("ResolveServers = %v, want nil", err)
		}
	})
}
