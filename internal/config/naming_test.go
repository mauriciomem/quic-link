package config_test

// naming_test.go enforces what names_baseline_test.go recorded as missing
// before this: the [names] table and every server name are now checked, and
// the two keys that shipped as reserved are refused with a reason.
//
// The most important case in this file is a suffix of ".". It is one line of
// configuration, and accepting it would point the whole machine's DNS at
// quic-link.

import (
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/config"
)

// loadAndValidate is the path a real client takes: read the file, then check it
// for the client role.
func loadAndValidate(t *testing.T, body string) error {
	t.Helper()
	unsetAllQLEnv(t)
	cfg, err := config.Load(writeConfig(t, "schema = 1\n"+body))
	if err != nil {
		return err
	}
	_, err = cfg.Validate(config.RoleClient)
	return err
}

// mustRefuse asserts the config is refused and that the message contains a
// phrase a reader would need in order to fix it.
func mustRefuse(t *testing.T, body, wantPhrase string) {
	t.Helper()
	err := loadAndValidate(t, body)
	if err == nil {
		t.Fatal("want a refusal, got none")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("refusal must wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), wantPhrase) {
		t.Fatalf("message should contain %q so the reader knows what to do; got: %v", wantPhrase, err)
	}
}

// ---- suffix -----------------------------------------------------------------

// TestSuffix_RootIsRefused is the single highest-value assertion in the phase.
// On a systemd machine a suffix of "." becomes the routing-domain wildcard,
// which sends every name lookup on the host to our responder.
func TestSuffix_RootIsRefused(t *testing.T) {
	mustRefuse(t, "[names]\nsuffix = \".\"\n", "every lookup on this machine")
}

func TestSuffix_DangerousValuesAreRefused(t *testing.T) {
	cases := []struct {
		name, suffix, want string
	}{
		{"public TLD", "com", "not a name reserved for private use"},
		{"another public TLD", "io", "not a name reserved for private use"},
		{"a real domain", "example.com", "not a name reserved for private use"},
		{"multicast DNS", "local", "multicast DNS"},
		{"loopback name", "localhost", "handled specially by resolvers"},
		{"whitespace padding", " internal", "whitespace"},
		{"a space inside", "not a hostname", "not a valid label"},
		{"leading dash", "-bad", "not a valid label"},
		{"trailing dash", "bad-", "not a valid label"},
		{"underscore", "my_zone", "not a valid label"},
		{"empty label", "a..b", "not a valid label"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustRefuse(t, "[names]\nsuffix = \""+tc.suffix+"\"\n", tc.want)
		})
	}
}

func TestSuffix_ReservedNamesAreAccepted(t *testing.T) {
	for _, s := range []string{"internal", "lab.internal", "home.arpa", "x.home.arpa", "test", "dev.test"} {
		t.Run(s, func(t *testing.T) {
			if err := loadAndValidate(t, "[names]\nsuffix = \""+s+"\"\n"); err != nil {
				t.Fatalf("%q is reserved for private use and must be accepted: %v", s, err)
			}
		})
	}
}

// TestSuffix_AnchoredAtALabelBoundary guards the reserved-name check against
// the classic suffix-matching mistake: "notinternal" must not pass merely
// because it ends with the letters of a reserved name.
func TestSuffix_AnchoredAtALabelBoundary(t *testing.T) {
	for _, s := range []string{"notinternal", "myinternal", "xtest"} {
		t.Run(s, func(t *testing.T) {
			mustRefuse(t, "[names]\nsuffix = \""+s+"\"\n", "not a name reserved for private use")
		})
	}
}

// TestSuffix_OwnedDomainNeedsAnExplicitClaim pins the escape hatch: a real
// domain is usable, but only once the operator has said it is theirs.
func TestSuffix_OwnedDomainNeedsAnExplicitClaim(t *testing.T) {
	mustRefuse(t, "[names]\nsuffix = \"srv.example.com\"\n", "suffix_is_mine")

	if err := loadAndValidate(t, "[names]\nsuffix = \"srv.example.com\"\nsuffix_is_mine = true\n"); err != nil {
		t.Fatalf("an acknowledged domain must be accepted: %v", err)
	}
}

// TestSuffix_NormalizedForm pins that what the rest of the program receives is
// lowercase and has no trailing dot, whatever spelling was written.
func TestSuffix_NormalizedForm(t *testing.T) {
	for _, written := range []string{"INTERNAL", "Internal", "internal.", "INTERNAL."} {
		t.Run(written, func(t *testing.T) {
			unsetAllQLEnv(t)
			cfg, err := config.Load(writeConfig(t, "schema = 1\n[names]\nsuffix = \""+written+"\"\n"))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			n, err := cfg.Naming()
			if err != nil {
				t.Fatalf("Naming: %v", err)
			}
			if n.Suffix != "internal" {
				t.Errorf("suffix %q resolved to %q, want %q", written, n.Suffix, "internal")
			}
		})
	}
}

// ---- ports ------------------------------------------------------------------

// TestPorts_PrivilegedIsRefusedAtConfigTime pins where the no-privileged-bind
// rule is actually enforced. A privileged port must be refused when the file is
// read, not discovered as a permission error once the daemon is starting.
func TestPorts_PrivilegedIsRefusedAtConfigTime(t *testing.T) {
	for _, key := range []string{"dns_port", "http_port", "https_port"} {
		t.Run(key, func(t *testing.T) {
			mustRefuse(t, "[names]\n"+key+" = 53\n", "reserves for privileged processes")
			mustRefuse(t, "[names]\n"+key+" = 1023\n", "reserves for privileged processes")
		})
	}
}

func TestPorts_OutOfRangeIsRefused(t *testing.T) {
	for _, v := range []string{"-1", "65536", "99999"} {
		t.Run(v, func(t *testing.T) {
			mustRefuse(t, "[names]\ndns_port = "+v+"\n", "is not a port number")
		})
	}
}

// TestPorts_CollisionIsRefused pins that two listeners cannot be told to share
// a port. Left to run, the second bind fails at startup with nothing to say why.
func TestPorts_CollisionIsRefused(t *testing.T) {
	mustRefuse(t, "[names]\ndns_port = 20000\nhttp_port = 20000\n", "each listener needs its own port")
	mustRefuse(t, "[names]\nhttp_port = 21000\nhttps_port = 21000\n", "each listener needs its own port")
}

// TestPorts_DefaultsAreUnprivilegedAndDistinct pins the shipped values. The DNS
// default in particular must not go back to 5355, which is a registered port
// that a stock resolver already holds.
func TestPorts_DefaultsAreUnprivilegedAndDistinct(t *testing.T) {
	unsetAllQLEnv(t)
	cfg, err := config.Load(writeConfig(t, "schema = 1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	n, err := cfg.Naming()
	if err != nil {
		t.Fatalf("Naming with no [names] table must succeed: %v", err)
	}
	if n.Suffix != config.DefaultSuffix {
		t.Errorf("default suffix = %q, want %q", n.Suffix, config.DefaultSuffix)
	}
	// Exact, not a range: a typo turning 18080 into 18081 would sail through a
	// bounds check, and the resolver file init writes names one specific number.
	if n.DNSPort != config.DefaultDNSPort || n.HTTPPort != config.DefaultHTTPPort || n.HTTPSPort != config.DefaultHTTPSPort {
		t.Errorf("defaults = %d/%d/%d, want %d/%d/%d",
			n.DNSPort, n.HTTPPort, n.HTTPSPort,
			config.DefaultDNSPort, config.DefaultHTTPPort, config.DefaultHTTPSPort)
	}
	ports := map[string]int{"dns": n.DNSPort, "http": n.HTTPPort, "https": n.HTTPSPort}
	seen := map[int]string{}
	for name, p := range ports {
		if p < 1024 || p > 65535 {
			t.Errorf("default %s port %d is not an unprivileged port", name, p)
		}
		if other, dup := seen[p]; dup {
			t.Errorf("default %s and %s ports are both %d", other, name, p)
		}
		seen[p] = name
	}
	if n.DNSPort == 5355 {
		t.Error("5355 is the registered LLMNR port and a stock systemd-resolved already holds it")
	}
}

// ---- server names -----------------------------------------------------------

// TestServerName_MustBeAHostnameLabel pins the tightening: a server name is now
// the first part of a hostname, so it has to be able to be one.
func TestServerName_MustBeAHostnameLabel(t *testing.T) {
	pin := mustPin(t)
	body := func(name string) string {
		return "[servers.\"" + name + "\"]\naddr = \"host:7443\"\npin = \"" + pin + "\"\n"
	}

	for _, bad := range []string{"My_Server", "server one", "UPPER", "-leading", "trailing-", "a.b", "srv_1"} {
		t.Run("refused/"+bad, func(t *testing.T) {
			err := loadAndValidate(t, body(bad))
			if err == nil {
				t.Fatalf("server name %q cannot be a hostname label and must be refused", bad)
			}
			if !strings.Contains(err.Error(), "servers."+bad) {
				t.Errorf("the message must name the offending server; got: %v", err)
			}
		})
	}
	for _, good := range []string{"server1", "gpu-box", "a", "s1-prod-eu"} {
		t.Run("accepted/"+good, func(t *testing.T) {
			if err := loadAndValidate(t, body(good)); err != nil {
				t.Fatalf("server name %q is a valid hostname label: %v", good, err)
			}
		})
	}
}

// TestServerName_UppercaseGetsItsOwnReason checks that the most likely mistake
// is explained rather than lumped in with the generic character rule.
func TestServerName_UppercaseGetsItsOwnReason(t *testing.T) {
	if err := config.ValidateServerName("Server1"); err == nil {
		t.Fatal("want a refusal")
	} else if !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("an uppercase name should be told it must be lowercase; got: %v", err)
	}
}

// ---- removed keys -----------------------------------------------------------

// TestRemovedKeys_ExplainThemselves pins the decision that a key which shipped
// as documented-and-reserved is refused with its reason, not reported as an
// unknown key. "Unknown key" reads like a typo, and these are not typos.
func TestRemovedKeys_ExplainThemselves(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"ports table", "[ports]\nmode = \"auto\"\n", "no longer used"},
		{"ports table reason", "[ports]\nmode = \"auto\"\n", "does not bind ports the operating system reserves"},
		{"names.block", "[names]\nblock = \"127.42.0.0/16\"\n", "no longer used"},
		{"names.block reason", "[names]\nblock = \"127.42.0.0/16\"\n", "no address range to set aside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unsetAllQLEnv(t)
			_, err := config.Load(writeConfig(t, "schema = 1\n"+tc.body))
			if err == nil {
				t.Fatal("want a refusal")
			}
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("must wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("message should contain %q; got: %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "unknown key or table") {
				t.Fatalf("a removed key must not be reported as merely unknown; got: %v", err)
			}
		})
	}
}

// TestRemovedEnvVars_ExplainThemselves pins the same treatment for the
// environment, which would otherwise ignore them in silence.
func TestRemovedEnvVars_ExplainThemselves(t *testing.T) {
	for _, key := range []string{"QUIC_LINK_PORTS_MODE", "QUIC_LINK_NAMES_BLOCK"} {
		t.Run(key, func(t *testing.T) {
			unsetAllQLEnv(t)
			setEnv(t, key, "whatever")
			_, err := config.Load(writeConfig(t, "schema = 1\n"))
			if err == nil {
				t.Fatalf("%s was removed; setting it must not be ignored in silence", key)
			}
			if !strings.Contains(err.Error(), "no longer used") {
				t.Fatalf("message should say it is no longer used; got: %v", err)
			}
		})
	}
}

// TestNewEnvVarsApply pins that the naming ports can be set from the
// environment, matching every other scalar key.
func TestNewEnvVarsApply(t *testing.T) {
	unsetAllQLEnv(t)
	setEnv(t, "QUIC_LINK_NAMES_SUFFIX", "lab.internal")
	setEnv(t, "QUIC_LINK_NAMES_DNS_PORT", "25353")
	setEnv(t, "QUIC_LINK_NAMES_HTTP_PORT", "28080")
	setEnv(t, "QUIC_LINK_NAMES_HTTPS_PORT", "28443")

	cfg, err := config.Load(writeConfig(t, "schema = 1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	n, err := cfg.Naming()
	if err != nil {
		t.Fatalf("Naming: %v", err)
	}
	if n.Suffix != "lab.internal" || n.DNSPort != 25353 || n.HTTPPort != 28080 || n.HTTPSPort != 28443 {
		t.Errorf("environment overrides not applied: %+v", n)
	}
}

// ---- role scoping -----------------------------------------------------------

// TestBadNamesIsOnlyAWarningForAnAgent pins that the naming layer is
// client-side: an agent sharing a config file with a bad [names] table is told,
// but not stopped, because it never serves a name.
func TestBadNamesIsOnlyAWarningForAnAgent(t *testing.T) {
	unsetAllQLEnv(t)
	pin := mustPin(t)
	cfg, err := config.Load(writeConfig(t, "schema = 1\n"+
		"[names]\nsuffix = \".\"\n"+
		"[agent]\nlisten = \":7443\"\nauthorized_clients = [\""+pin+"\"]\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	warns, err := cfg.Validate(config.RoleAgent)
	if err != nil {
		t.Fatalf("an agent must not be stopped by a client-side naming problem: %v", err)
	}
	var found bool
	for _, w := range warns {
		if strings.Contains(w, "names") {
			found = true
		}
	}
	if !found {
		t.Errorf("the agent should still be warned; warnings were %v", warns)
	}
}

// TestFlagOnlyServerNameIsAccepted pins the one name that is exempt from the
// hostname rule. A verb given --server and --pin with no config file builds a
// server on the spot and validates it under this key; refusing the key would
// break every flag-only invocation, which is how somebody uses the tool before
// they have written a config file at all.
//
// This is a regression test with a story: adding the hostname rule broke
// exactly this path, and it was caught only because the whole package was run.
func TestFlagOnlyServerNameIsAccepted(t *testing.T) {
	if err := config.ValidateServerName(config.FlagOnlyServerName); err != nil {
		t.Fatalf("the flag-only sentinel must stay usable: %v", err)
	}
	// The exemption is exact. Anything merely shaped like the sentinel is still
	// refused, so it can never be reached by accident.
	for _, near := range []string{"(flag)", "(FLAGS)", "((flags))", "(flags", "flags)"} {
		if err := config.ValidateServerName(near); err == nil {
			t.Errorf("%q must not be accepted; only the exact sentinel is exempt", near)
		}
	}
	// "flags" without the parentheses is a perfectly ordinary hostname label and
	// is accepted on its own merits — it has nothing to do with the sentinel.
	if err := config.ValidateServerName("flags"); err != nil {
		t.Errorf("plain %q is a valid label and must be accepted: %v", "flags", err)
	}
}

// TestSuffix_InfrastructureZoneIsRefusedEvenWhenClaimed pins that the
// "I control this domain" flag cannot unlock a zone nobody can control.
func TestSuffix_InfrastructureZoneIsRefusedEvenWhenClaimed(t *testing.T) {
	for _, s := range []string{"arpa", "in-addr.arpa", "ip6.arpa", "e164.arpa"} {
		t.Run(s, func(t *testing.T) {
			mustRefuse(t, "[names]\nsuffix = \""+s+"\"\n", "nobody can control")
			// And the escape hatch must NOT open it.
			err := loadAndValidate(t, "[names]\nsuffix = \""+s+"\"\nsuffix_is_mine = true\n")
			if err == nil {
				t.Fatalf("%q must stay refused even when claimed", s)
			}
		})
	}
	// home.arpa is the carve-out and must still work, with or without the flag.
	for _, s := range []string{"home.arpa", "lab.home.arpa"} {
		if err := loadAndValidate(t, "[names]\nsuffix = \""+s+"\"\n"); err != nil {
			t.Errorf("%q is set aside for exactly this use: %v", s, err)
		}
	}
}
