package config

import (
	"errors"
	"strings"
	"testing"
)

// TestDialableAddrRefusesWhatCanNeverWork covers addresses that are wrong on
// their face. Each one is wrong for a reason no change in the network could
// repair, which is what separates them from an address that merely fails today.
func TestDialableAddrRefusesWhatCanNeverWork(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"empty", ""},
		{"no port", "1.2.3.4"},
		{"prose", "this is not an address at all"},
		{"two ports", "host:7443:extra"},
		{"unbracketed IPv6", "fd3e:5c82:9b1a:1::20:7443"},
		{"unbracketed loopback IPv6", "::1:7443"},
		{"port only", ":7443"},
		{"IPv6 literal", "[fd3e:5c82:9b1a:1::20]:7443"},
		{"IPv6 loopback literal", "[::1]:7443"},
		{"IPv6 link-local with zone", "[fe80::1%eth0]:7443"},
	}
	for _, tc := range cases {
		err := DialableAddr("web", tc.addr)
		if err == nil {
			t.Errorf("%s: DialableAddr(%q) allowed an address that can never work", tc.name, tc.addr)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: DialableAddr(%q) error does not report itself as a configuration "+
				"problem, so it would not reach the exit code reserved for one: %v", tc.name, tc.addr, err)
		}
		if !strings.Contains(err.Error(), "web") {
			t.Errorf("%s: error does not name the server, leaving the operator to guess which "+
				"one to fix: %v", tc.name, err)
		}
		if tc.addr != "" && !strings.Contains(err.Error(), tc.addr) {
			t.Errorf("%s: error does not quote the offending address: %v", tc.name, err)
		}
	}
}

// TestDialableAddrAllowsWhatMightWork is the other half, and the half that
// stops this check growing teeth it should not have. Every entry here fails to
// connect in some circumstance, and every one must still be allowed to try:
// refusing them would turn a host being switched off, or a name not yet in DNS,
// into a program that will not start.
//
// Several are drawn from addresses the test suite itself uses, so a stricter
// rule than this one would be caught here rather than by a puzzling failure
// somewhere else.
func TestDialableAddrAllowsWhatMightWork(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"IPv4 literal", "1.2.3.4:7443"},
		{"hostname", "agent.example.com:7443"},
		{"hostname that does not resolve", "no-such-host-abcxyz.invalid:7443"},
		{"closed port", "127.0.0.1:9999"},
		{"private address", "192.168.1.50:7443"},
		{"short hostname", "healthy-agent:1"},
		{"port zero", "127.0.0.1:0"},
		{"named port", "127.0.0.1:domain"},
		{"named port https", "127.0.0.1:https"},
		{"IPv4-mapped IPv6", "[::ffff:1.2.3.4]:7443"},
		{"localhost", "localhost:7443"},
	}
	for _, tc := range cases {
		if err := DialableAddr("web", tc.addr); err != nil {
			t.Errorf("%s: DialableAddr(%q) refused an address that could work, which would stop "+
				"the program starting over something a retry may fix: %v", tc.name, tc.addr, err)
		}
	}
}
