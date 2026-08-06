package names_test

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/mauriciomem/quic-link/internal/names"
)

func testZone() *names.Zone { return names.NewZone("internal", []string{"server1", "gpu-box"}) }

// query builds a realistic query: one question, recursion desired, and an
// options record, because that is what a system resolver actually sends.
func query(t *testing.T, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	out, err := buildQuery(name, typ, edns)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// buildQuery is the same thing without a test to report to, so a fuzz seed can
// use it. Test inputs are fixed strings, so a failure here is a bug in the test
// itself and stopping is the right response.
func buildQuery(name string, typ dnsmessage.Type, edns bool) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xbeef, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
			return nil, err
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

type parsed struct {
	rcode              dnsmessage.RCode
	question           string
	answers            []dnsmessage.Resource
	authoritative      bool
	recursionAvailable bool
}

func parseReply(t *testing.T, msg []byte) parsed {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatalf("reply does not parse: %v", err)
	}
	if !m.Header.Response {
		t.Error("reply is not marked as a response")
	}
	p := parsed{
		rcode:              m.Header.RCode,
		answers:            m.Answers,
		authoritative:      m.Header.Authoritative,
		recursionAvailable: m.Header.RecursionAvailable,
	}
	if len(m.Questions) == 1 {
		p.question = m.Questions[0].Name.String()
	}
	return p
}

// TestRespond_BehaviourTable is the authoritative statement of what this
// responder says to everything. Each row asserts the response code exactly —
// the difference between "does not exist" and "exists but has no address of
// that kind" lives entirely in that code, and a test that only checked for the
// absence of an answer would pass for both.
func TestRespond_BehaviourTable(t *testing.T) {
	z := testZone()
	cases := []struct {
		name       string
		qname      string
		qtype      dnsmessage.Type
		wantRCode  dnsmessage.RCode
		wantAnswer bool
	}{
		{"a known server", "server1.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, true},
		{"another known server", "gpu-box.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, true},
		{"a service on a known server", "grafana.server1.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, true},
		{"a deeply nested service", "a.b.server1.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, true},

		{"v6 address for a known name", "server1.internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, false},
		{"mail record for a known name", "server1.internal.", dnsmessage.TypeMX, dnsmessage.RCodeSuccess, false},
		{"a request for everything", "server1.internal.", dnsmessage.TypeALL, dnsmessage.RCodeSuccess, false},
		{"service discovery for a known name", "server1.internal.", dnsmessage.TypeSRV, dnsmessage.RCodeSuccess, false},

		{"an unknown server", "nope.internal.", dnsmessage.TypeA, dnsmessage.RCodeNameError, false},
		{"a service on an unknown server", "grafana.nope.internal.", dnsmessage.TypeA, dnsmessage.RCodeNameError, false},
		{"v6 for an unknown server", "nope.internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeNameError, false},

		{"the zone itself", "internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, false},

		{"a name outside the zone", "example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, false},
		{"a name that merely ends in the letters", "notinternal.", dnsmessage.TypeA, dnsmessage.RCodeRefused, false},
		{"the zone name used as a prefix", "internal.evil.example.", dnsmessage.TypeA, dnsmessage.RCodeRefused, false},
		{"the root-adjacent infrastructure zone", "1.0.0.127.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeRefused, false},

		{"the resolver capability probe", "_dns.resolver.arpa.", dnsmessage.TypeSVCB, dnsmessage.RCodeSuccess, false},
		{"the probe asked as an address", "_dns.resolver.arpa.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, false},
		{"something merely under the probe name", "foo._dns.resolver.arpa.", dnsmessage.TypeSVCB, dnsmessage.RCodeRefused, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, edns := range []bool{false, true} {
				reply, drop := names.Respond(query(t, tc.qname, tc.qtype, edns), z)
				if drop {
					t.Fatalf("edns=%v: a well-formed query must be answered, not dropped", edns)
				}
				got := parseReply(t, reply)
				if got.rcode != tc.wantRCode {
					t.Errorf("edns=%v: rcode = %v, want %v", edns, got.rcode, tc.wantRCode)
				}
				if hasAnswer := len(got.answers) > 0; hasAnswer != tc.wantAnswer {
					t.Errorf("edns=%v: answers = %d, want any = %v", edns, len(got.answers), tc.wantAnswer)
				}
				if got.question != tc.qname {
					t.Errorf("edns=%v: question echoed as %q, want %q", edns, got.question, tc.qname)
				}
				if got.recursionAvailable {
					t.Errorf("edns=%v: recursion must never be offered", edns)
				}
			}
		})
	}
}

// TestRespond_AddressAnswerShape pins what an address answer actually contains.
// The lifetime is asserted exactly: a range would accept any value at all.
func TestRespond_AddressAnswerShape(t *testing.T) {
	reply, drop := names.Respond(query(t, "grafana.server1.internal.", dnsmessage.TypeA, true), testZone())
	if drop {
		t.Fatal("dropped")
	}
	got := parseReply(t, reply)
	if !got.authoritative {
		t.Error("we are the only source for this zone and must say so")
	}
	if len(got.answers) != 1 {
		t.Fatalf("answers = %d, want exactly 1", len(got.answers))
	}
	a := got.answers[0]
	if a.Header.TTL != 5 {
		t.Errorf("ttl = %d, want exactly 5", a.Header.TTL)
	}
	if a.Header.Name.String() != "grafana.server1.internal." {
		t.Errorf("answer name = %q", a.Header.Name.String())
	}
	body, ok := a.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer body is %T, want an address", a.Body)
	}
	if ip := net.IP(body.A[:]); !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("address = %v, want 127.0.0.1", ip)
	}
}

// TestRespond_EchoesTheQuestionCaseExactly guards a property no "does it
// resolve" test can see. Some resolvers vary the case of the name they ask
// about and compare it on the way back, so a reply that helpfully lowercases
// the question is thrown away as a forgery — while every other test still
// passes.
func TestRespond_EchoesTheQuestionCaseExactly(t *testing.T) {
	const asked = "GrAfAnA.Server1.INTERNAL."
	reply, drop := names.Respond(query(t, asked, dnsmessage.TypeA, false), testZone())
	if drop {
		t.Fatal("a mixed-case name must still resolve")
	}
	got := parseReply(t, reply)
	if got.question != asked {
		t.Errorf("question echoed as %q, want %q byte for byte", got.question, asked)
	}
	if len(got.answers) != 1 {
		t.Fatalf("mixed case must not change the answer: got %d answers", len(got.answers))
	}
	if n := got.answers[0].Header.Name.String(); n != asked {
		t.Errorf("answer name = %q, want the name as asked %q", n, asked)
	}
}

// TestRespond_MalformedInputIsDroppedNotAnswered covers what arrives when
// something other than a resolver is talking to the socket.
func TestRespond_MalformedInputIsDroppedNotAnswered(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"one byte":         {0x00},
		"truncated header": {0x12, 0x34, 0x01},
		"header only":      make([]byte, 12),
		"garbage":          bytes.Repeat([]byte{0xff}, 40),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			reply, drop := names.Respond(in, testZone())
			if !drop && len(reply) == 0 {
				t.Error("either drop or produce a reply, never an empty one")
			}
		})
	}
}

// TestRespond_IgnoresAReplyArrivingAsAQuery: answering something already marked
// as a response would make this an easy reflector.
func TestRespond_IgnoresAReplyArrivingAsAQuery(t *testing.T) {
	q := query(t, "server1.internal.", dnsmessage.TypeA, false)
	q[2] |= 0x80 // set the response bit
	if _, drop := names.Respond(q, testZone()); !drop {
		t.Error("a message already marked as a response must be ignored")
	}
}

// TestRespond_MultipleQuestionsAreRefusedAsMalformed: nothing in practice asks
// two things at once, and answering several is where both complexity and
// amplification would come from.
func TestRespond_MultipleQuestionsAreRefusedAsMalformed(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	_ = b.StartQuestions()
	for _, n := range []string{"server1.internal.", "gpu-box.internal."} {
		_ = b.Question(dnsmessage.Question{
			Name: dnsmessage.MustNewName(n), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		})
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	reply, drop := names.Respond(msg, testZone())
	if drop {
		t.Fatal("two questions should be answered with a complaint, not silence")
	}
	if got := parseReply(t, reply); got.rcode != dnsmessage.RCodeFormatError {
		t.Errorf("rcode = %v, want a format complaint", got.rcode)
	}
}

// TestRespond_CannotAmplify: every reply is small, and the ones carrying no
// answer are no larger than the question that prompted them. Loopback makes
// this mostly theoretical, but the property is cheap to keep and expensive to
// notice the absence of.
func TestRespond_CannotAmplify(t *testing.T) {
	z := testZone()
	for _, n := range []string{
		"server1.internal.", "nope.internal.", "example.com.",
		"_dns.resolver.arpa.", "a.very.long.name.that.goes.on.server1.internal.",
	} {
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeALL} {
			q := query(t, n, typ, true)
			reply, drop := names.Respond(q, z)
			if drop {
				continue
			}
			if len(reply) > 512 {
				t.Errorf("%s/%v: reply is %d bytes, larger than anything this responder should send", n, typ, len(reply))
			}
			if ratio := float64(len(reply)) / float64(len(q)); ratio > 1.5 {
				t.Errorf("%s/%v: reply is %.2fx the query; this responder must not be worth aiming at anything", n, typ, ratio)
			}
		}
	}
}

// FuzzRespond: the parser is fed whatever arrives on a loopback port, so the
// only thing that must never happen is a panic or an unbounded reply.
func FuzzRespond(f *testing.F) {
	z := testZone()
	seed, err := buildQuery("server1.internal.", dnsmessage.TypeA, true)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, in []byte) {
		reply, drop := names.Respond(in, z)
		if !drop && len(reply) > 512 {
			t.Fatalf("reply of %d bytes from a %d byte input", len(reply), len(in))
		}
	})
}
