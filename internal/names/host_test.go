package names_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/names"
)

func req(lines ...string) []byte {
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
}

// TestHostFromRequest_RefusesEveryAmbiguity is the anti-rebinding core on the
// parsing side. Every row here is a request two readers could disagree about,
// and disagreement is what lets a routing decision be steered.
func TestHostFromRequest_RefusesEveryAmbiguity(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"two host headers", req("GET / HTTP/1.1", "Host: a.internal", "Host: b.internal"), names.ErrAmbiguousHost},
		{"two host headers, different case", req("GET / HTTP/1.1", "Host: a.internal", "host: b.internal"), names.ErrAmbiguousHost},
		{"absolute target disagreeing with host", req("GET http://other.internal/ HTTP/1.1", "Host: a.internal"), names.ErrAmbiguousHost},
		{"no host at all", req("GET / HTTP/1.0"), names.ErrNoHost},
		{"empty host value", req("GET / HTTP/1.1", "Host:"), names.ErrNoHost},
		// The folded line is a well-formed header in its own right, so this
		// refusal can only come from the folding rule. An earlier version of
		// this case used a folded line with no colon, which was refused for
		// being malformed whether or not the folding rule existed — it looked
		// like it tested the rule and tested nothing.
		{"a continued header line", []byte("GET / HTTP/1.1\r\nHost: a.internal\r\nX-A: 1\r\n\tX-B: 2\r\n\r\n"), names.ErrMalformed},
		{"a continued line right after the request line", []byte("GET / HTTP/1.1\r\n Host: a.internal\r\n\r\n"), names.ErrMalformed},
		{"a stray carriage return", []byte("GET / HTTP/1.1\rHost: a.internal\r\n\r\n"), names.ErrMalformed},
		{"a null byte", []byte("GET / HTTP/1.1\r\nHost: a.inter\x00nal\r\n\r\n"), names.ErrMalformed},
		{"a request line with too few parts", req("GET /", "Host: a.internal"), names.ErrMalformed},
		{"a header with no colon", req("GET / HTTP/1.1", "Host: a.internal", "nonsense"), names.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := names.HostFromRequest(tc.in)
			if err == nil {
				t.Fatalf("want a refusal, got host %q", got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHostFromRequest_AcceptsWhatABrowserSends(t *testing.T) {
	cases := []struct {
		name, want string
		in         []byte
	}{
		{"ordinary", "grafana.server1.internal", req("GET / HTTP/1.1", "Host: grafana.server1.internal")},
		{"with a port", "grafana.server1.internal:18080", req("GET /x HTTP/1.1", "Host: grafana.server1.internal:18080")},
		{"no space after the colon", "a.internal", req("GET / HTTP/1.1", "Host:a.internal")},
		{"extra padding", "a.internal", req("GET / HTTP/1.1", "Host:   a.internal   ")},
		{"other headers around it", "a.internal", req("POST /x HTTP/1.1", "Accept: */*", "Host: a.internal", "Content-Length: 3")},
		{"absolute target agreeing", "a.internal", req("GET http://a.internal/x HTTP/1.1", "Host: a.internal")},
		{"absolute target agreeing, different case", "A.internal", req("GET http://a.internal/x HTTP/1.1", "Host: A.internal")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := names.HostFromRequest(tc.in)
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if got != tc.want {
				t.Errorf("host = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHostFromRequest_RefusesAProtocolWeDoNotSpeak: a client that opens with a
// version-2 preamble names no host in any form we read, so it is refused for
// the ordinary reason rather than needing a rule of its own.
func TestHostFromRequest_RefusesAProtocolWeDoNotSpeak(t *testing.T) {
	if _, err := names.HostFromRequest([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err == nil {
		t.Error("a version-2 preamble must not be routed")
	}
}

func TestNormalizeHost(t *testing.T) {
	ok := []struct{ in, want string }{
		{"grafana.server1.internal", "grafana.server1.internal"},
		{"GRAFANA.Server1.INTERNAL", "grafana.server1.internal"},
		{"a.internal:18080", "a.internal"},
		{"a.internal.", "a.internal"},
		{"A.Internal.:443", "a.internal"},
		{"xn--bcher-kva.internal", "xn--bcher-kva.internal"},
	}
	for _, tc := range ok {
		got, err := names.NormalizeHost(tc.in)
		if err != nil {
			t.Errorf("NormalizeHost(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	bad := map[string]error{
		"127.0.0.1":        names.ErrHostIsAddress,
		"127.0.0.1:18080":  names.ErrHostIsAddress,
		"10.0.0.1":         names.ErrHostIsAddress,
		"[::1]":            names.ErrHostIsAddress,
		"[::1]:8080":       names.ErrHostIsAddress,
		"[2001:db8::1]":    names.ErrHostIsAddress,
		"user@a.internal":  names.ErrMalformed,
		"a b.internal":     names.ErrMalformed,
		"a.internal:xyz":   names.ErrMalformed,
		":18080":           names.ErrNoHost,
		"":                 names.ErrNoHost,
		"-bad.internal":    names.ErrMalformed,
		"bad-.internal":    names.ErrMalformed,
		"a..internal":      names.ErrMalformed,
		"a_b.internal":     names.ErrMalformed,
		"ünïcode.internal": names.ErrMalformed,
	}
	for in, want := range bad {
		got, err := names.NormalizeHost(in)
		if err == nil {
			t.Errorf("NormalizeHost(%q) = %q, want a refusal", in, got)
			continue
		}
		if !errors.Is(err, want) {
			t.Errorf("NormalizeHost(%q): error = %v, want %v", in, err, want)
		}
	}
}

// TestRoute_PortIsStrippedBeforeTheZoneIsChecked is the ordering trap, written
// out as a test because getting it wrong refuses every honest request and the
// obvious cure reopens the hole.
func TestRoute_PortIsStrippedBeforeTheZoneIsChecked(t *testing.T) {
	z := names.NewZone("internal", []string{"server1"})

	server, service, host, err := z.Route("grafana.server1.internal:18080")
	if err != nil {
		t.Fatalf("a browser on a non-standard port must be routed: %v", err)
	}
	if server != "server1" || service != "grafana" || host != "grafana.server1.internal" {
		t.Errorf("got (%q,%q,%q)", server, service, host)
	}

	// And the same shape outside the zone is still refused, so the fix above
	// cannot have been "accept anything with the suffix somewhere in it".
	for _, bad := range []string{
		"grafana.server1.evil.example:18080",
		"internal.evil.example:18080",
		"notinternal:18080",
		"evil.example",
	} {
		if _, _, _, err := z.Route(bad); !errors.Is(err, names.ErrOutsideZone) {
			t.Errorf("Route(%q): error = %v, want outside-the-zone", bad, err)
		}
	}
}

func TestRoute_RefusesTheZoneItselfAndAddresses(t *testing.T) {
	z := names.NewZone("internal", []string{"server1"})
	for _, bad := range []string{"internal", "internal.", "127.0.0.1", "127.0.0.1:18080"} {
		if _, _, _, err := z.Route(bad); err == nil {
			t.Errorf("Route(%q) must be refused", bad)
		}
	}
}

func FuzzHostFromRequest(f *testing.F) {
	f.Add(req("GET / HTTP/1.1", "Host: a.internal"))
	f.Add(req("GET http://a.internal/ HTTP/1.1", "Host: a.internal"))
	f.Add([]byte("\r\n\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		host, err := names.HostFromRequest(in)
		if err != nil {
			return
		}
		// Anything accepted must survive normalisation without panicking, and
		// must not come back carrying bytes that could confuse a later reader.
		if n, err := names.NormalizeHost(host); err == nil {
			if strings.ContainsAny(n, " \t\r\n\x00@/") {
				t.Fatalf("normalised host %q carries bytes it should not", n)
			}
		}
	})
}
