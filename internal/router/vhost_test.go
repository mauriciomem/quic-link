package router

import "testing"

func TestValidateVhostKey(t *testing.T) {
	ok := []string{"grafana.server1.internal", "a.internal", "*.server1.internal", "*.internal", "x-y.z.internal"}
	for _, k := range ok {
		if err := ValidateVhostKey(k); err != nil {
			t.Errorf("ValidateVhostKey(%q): %v", k, err)
		}
	}
	bad := []string{"", "*", "*.", "a.*.b", "*foo.internal", "foo*.internal", "**.internal",
		"Grafana.internal", "a_b.internal", "-a.internal", "a-.internal", "a..internal"}
	for _, k := range bad {
		if err := ValidateVhostKey(k); err == nil {
			t.Errorf("ValidateVhostKey(%q) must be refused", k)
		}
	}
}

func TestVhosts_ExactBeatsWildcardAndLongestWins(t *testing.T) {
	v, err := newVhosts(map[string]string{
		"grafana.server1.internal": "tcp://127.0.0.1:3000",
		"*.server1.internal":       "tcp://127.0.0.1:9000",
		"*.internal":               "tcp://127.0.0.1:1000",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"grafana.server1.internal": "tcp://127.0.0.1:3000", // exact
		"logs.server1.internal":    "tcp://127.0.0.1:9000", // the more specific pattern
		"a.server2.internal":       "tcp://127.0.0.1:1000", // the broader one
	}
	// Run it many times: a resolver that asked each pattern in turn would give
	// a different answer depending on the order a map happened to be stored in,
	// and would look correct most of the time.
	for range 200 {
		for host, want := range cases {
			got, ok := v.resolve(host)
			if !ok {
				t.Fatalf("resolve(%q) found nothing", host)
			}
			if got.raw != want {
				t.Fatalf("resolve(%q) = %q, want %q", host, got.raw, want)
			}
		}
	}
}

// TestVhosts_WildcardIsAnchoredAtALabel: a pattern that could match part of a
// label would cover names it was never meant to.
func TestVhosts_WildcardIsAnchoredAtALabel(t *testing.T) {
	v, err := newVhosts(map[string]string{"*.foo.internal": "tcp://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range []string{"a.foo.internal", "b.foo.internal"} {
		if _, ok := v.resolve(hit); !ok {
			t.Errorf("resolve(%q) should match", hit)
		}
	}
	for _, miss := range []string{"xfoo.internal", "foo.internal", "a.foo.internal.evil", "foo.internal.evil"} {
		if _, ok := v.resolve(miss); ok {
			t.Errorf("resolve(%q) must NOT match", miss)
		}
	}
}

func TestVhosts_BadAddressIsRefusedAtBuildTime(t *testing.T) {
	if _, err := newVhosts(map[string]string{"a.internal": "not-an-address"}); err == nil {
		t.Fatal("a bad address must fail when the table is built, not when someone visits the name")
	}
}
