package names

import (
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// answerTTL is how long a resolver may cache what we say. It is deliberately
// tiny: answers are cheap to fetch again over loopback, and a short life keeps
// a stale answer from outliving a configuration change by more than a moment.
const answerTTL = 5

// loopback is the address every name in the zone resolves to. There is exactly
// one, and the request itself says which server it is for — an HTTP request
// carries the name in its Host header, a TLS handshake in its SNI.
var loopback = [4]byte{127, 0, 0, 1}

// resolverDiscoveryName is the name a system resolver queries to ask whether we
// offer an encrypted transport. It sits outside our suffix, so the general rule
// would refuse it; we answer "nothing here" instead, because refusing a
// resolver's capability probe is the sort of thing that produces a retry loop
// nobody diagnoses for a week.
//
// The match is exact. Anything merely ending in this name is not this name and
// falls through to the ordinary refusal, so the carve-out cannot become a hole.
const resolverDiscoveryName = "_dns.resolver.arpa"

// maxAnswerBytes bounds what we will ever send. Every reply is a header, an
// echoed question and at most one address, so this is generous; it exists so a
// test can assert the responder cannot be turned into an amplifier.
const maxAnswerBytes = 512

// Respond answers one DNS query.
//
// It returns the bytes to send back, or drop=true meaning send nothing at all.
// Silence is the right answer to something that is not a question: a malformed
// packet, or a reply that arrived where a query should be.
//
// The function is pure — no clock, no network, no state beyond the zone — so
// the entire behaviour of the responder can be tested without a socket.
func Respond(query []byte, z *Zone) (reply []byte, drop bool) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, true
	}
	// A response arriving on our socket is either a stray or a spoof attempt.
	// Answering it would make us a reflector.
	if h.Response {
		return nil, true
	}

	q, err := p.Question()
	if err != nil {
		// No question at all. Nothing to echo, so say the request was
		// malformed rather than staying silent — a resolver that sent this
		// deserves to know.
		return build(h, nil, dnsmessage.RCodeFormatError, false)
	}
	// Exactly one question, or none of this makes sense. Nothing in practice
	// sends more, and answering several is where complexity and amplification
	// would come from.
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return build(h, &q, dnsmessage.RCodeFormatError, false)
	}

	// Matching is case-insensitive. The echo is not: the question travels back
	// exactly as it arrived, because some resolvers randomise the case of a
	// query and compare it on the way back to detect a forged reply.
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))

	if name == resolverDiscoveryName {
		return build(h, &q, dnsmessage.RCodeSuccess, false)
	}

	// Outside our suffix we are not authoritative and say so, before looking at
	// anything else. Refusing rather than answering is what stops this being a
	// general-purpose resolver for whatever asks.
	if !z.InSuffix(name) {
		return build(h, &q, dnsmessage.RCodeRefused, false)
	}

	// A check run by the diagnosis verb. It is answered like any other name in
	// the zone, and remembered, so that verb can tell "the system resolver
	// reached us" from "something, somewhere, returned an address".
	if label, ok := probeLabel(name, z.suffix); ok {
		z.noteProbe(label)
		if q.Type != dnsmessage.TypeA {
			return build(h, &q, dnsmessage.RCodeSuccess, false)
		}
		return build(h, &q, dnsmessage.RCodeSuccess, true)
	}

	// The zone's own name exists but is not a server.
	if name == z.suffix {
		return build(h, &q, dnsmessage.RCodeSuccess, false)
	}

	server, _, ok := z.Split(name)
	if !ok || !z.Manages(server) {
		// The name does not exist. This is a different statement from "exists
		// but has no address of that kind", and resolvers treat them
		// differently, so the two must not be conflated.
		return build(h, &q, dnsmessage.RCodeNameError, false)
	}

	// The name exists. Whether we have anything to say about it depends on what
	// was asked: an address, yes; anything else, nothing — and never an
	// expansion, which is the one shape that would make this an amplifier.
	if q.Type != dnsmessage.TypeA {
		return build(h, &q, dnsmessage.RCodeSuccess, false)
	}
	return build(h, &q, dnsmessage.RCodeSuccess, true)
}

// build assembles a reply. When answer is true an address record for the
// question's own name is included; otherwise the reply carries the question and
// nothing else.
func build(req dnsmessage.Header, q *dnsmessage.Question, code dnsmessage.RCode, answer bool) ([]byte, bool) {
	b := dnsmessage.NewBuilder(make([]byte, 0, maxAnswerBytes), dnsmessage.Header{
		ID:       req.ID,
		Response: true,
		OpCode:   req.OpCode,
		// We are the only source for this zone; there is nothing behind us.
		Authoritative: true,
		// Recursion is neither offered nor performed, whatever was asked for.
		RecursionDesired:   req.RecursionDesired,
		RecursionAvailable: false,
		RCode:              code,
	})
	b.EnableCompression()

	if q != nil {
		if err := b.StartQuestions(); err != nil {
			return nil, true
		}
		if err := b.Question(*q); err != nil {
			return nil, true
		}
	}
	if answer && q != nil {
		if err := b.StartAnswers(); err != nil {
			return nil, true
		}
		err := b.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   answerTTL,
		}, dnsmessage.AResource{A: loopback})
		if err != nil {
			return nil, true
		}
	}

	out, err := b.Finish()
	if err != nil {
		return nil, true
	}
	return out, false
}

// probeLabel matches <label>._probe.<suffix> and returns the label.
func probeLabel(name, suffix string) (string, bool) {
	tail := "." + ProbeLabel + "." + suffix
	if !strings.HasSuffix(name, tail) {
		return "", false
	}
	label := strings.TrimSuffix(name, tail)
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}
