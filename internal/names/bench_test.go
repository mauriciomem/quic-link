package names_test

// Benchmarks for the parsers on the per-request path.
//
// These exist to make a performance claim checkable rather than arguable. Two
// things are worth knowing before reading a number here.
//
// First, what is being measured is small in absolute terms. Every CPU-bound step
// in accepting one connection — finding the end of a header block, parsing the
// Host, normalising it, or reading a name out of a TLS ClientHello — sums to a
// few microseconds, against a local round trip measured in hundreds. These
// numbers do not decide whether the tool feels fast. They decide whether a change
// to a parser made it quantitatively worse, which is a different and answerable
// question.
//
// Second, the allocation columns are the stable ones. Time per operation varies
// by a few percent on an idle machine and by ten to twenty on a shared CI runner,
// which is enough to hide any regression worth finding. Allocations per operation
// are a property of the code and do not move at all between runs. Read B/op and
// allocs/op first; treat ns/op as a hint.
//
// The adversarial inputs are deliberate. Malformed, truncated and out-of-zone
// cases are the ones an unknown client reaches, they are already covered by this
// package's fuzz targets, and the asymmetry between them and the success path is
// itself a useful fact: rejecting junk should not cost more than serving a
// request.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/names"
)

// A request of the shape a browser actually sends, rather than the two-line
// minimum a hand-written fixture tends to use.
func browserRequest(host string) []byte {
	return []byte("GET /dashboard HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
		"Accept-Language: en-GB,en;q=0.9\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Connection: keep-alive\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"\r\n")
}

func BenchmarkHeaderEnd(b *testing.B) {
	req := browserRequest("grafana.server1.internal")
	b.ReportAllocs()
	b.SetBytes(int64(len(req)))
	for b.Loop() {
		names.HeaderEnd(req)
	}
}

// BenchmarkHeaderEnd_NotYetComplete measures the case the edge hits on every
// read before the last one: the header block is incomplete, so the scan runs to
// the end and finds nothing. An edge re-scans a growing buffer as bytes arrive,
// so this path runs more often than the successful one.
func BenchmarkHeaderEnd_NotYetComplete(b *testing.B) {
	req := browserRequest("grafana.server1.internal")
	partial := req[:len(req)-4]
	b.ReportAllocs()
	b.SetBytes(int64(len(partial)))
	for b.Loop() {
		names.HeaderEnd(partial)
	}
}

func BenchmarkHostFromRequest(b *testing.B) {
	req := browserRequest("grafana.server1.internal")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := names.HostFromRequest(req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHostFromRequest_ManyHeaders shows how the cost scales with the number
// of header lines, which is what a request carrying a large cookie jar looks
// like. The interesting output is the allocation delta against the benchmark
// above, not the time.
func BenchmarkHostFromRequest_ManyHeaders(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("GET /dashboard HTTP/1.1\r\nHost: grafana.server1.internal\r\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&sb, "X-Padding-%02d: %s\r\n", i, strings.Repeat("v", 48))
	}
	sb.WriteString("\r\n")
	req := []byte(sb.String())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := names.HostFromRequest(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizeHost(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := names.NormalizeHost("Grafana.Server1.Internal:18080"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSNIFromClientHello(b *testing.B) {
	hello := realClientHello(b, "grafana.server1.internal")
	b.ReportAllocs()
	b.SetBytes(int64(len(hello)))
	for b.Loop() {
		host, need, err := names.SNIFromClientHello(hello)
		if err != nil || need || host == "" {
			b.Fatalf("host=%q need=%v err=%v", host, need, err)
		}
	}
}

// BenchmarkSNIFromClientHello_Incomplete measures the reply the edge gives while
// it is still waiting for the rest of the record, which happens at least once per
// HTTPS connection.
func BenchmarkSNIFromClientHello_Incomplete(b *testing.B) {
	hello := realClientHello(b, "grafana.server1.internal")
	partial := hello[:16]
	b.ReportAllocs()
	for b.Loop() {
		if _, need, err := names.SNIFromClientHello(partial); err != nil || !need {
			b.Fatalf("need=%v err=%v", need, err)
		}
	}
}

func benchZone(b *testing.B) *names.Zone {
	b.Helper()
	z, err := names.NewZone("internal", []string{"server1", "gpu-box"})
	if err != nil {
		b.Fatalf("NewZone: %v", err)
	}
	return z
}

// dnsQuery builds a wire-format A query for name, which is what the responder
// reads off the socket.
func dnsQuery(name string, qtype byte) []byte {
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00, 0x00, qtype, 0x00, 0x01)
	return q
}

func BenchmarkRespond_A_Hit(b *testing.B) {
	z := benchZone(b)
	q := dnsQuery("grafana.server1.internal", 0x01)
	b.ReportAllocs()
	for b.Loop() {
		reply, drop := names.Respond(q, z)
		if drop || len(reply) == 0 {
			b.Fatalf("drop=%v len=%d", drop, len(reply))
		}
	}
}

// BenchmarkRespond_A_Miss measures a name inside the suffix whose server is not
// configured, which is the answer a dictionary scan of the zone would provoke.
func BenchmarkRespond_A_Miss(b *testing.B) {
	z := benchZone(b)
	q := dnsQuery("grafana.nosuchserver.internal", 0x01)
	b.ReportAllocs()
	for b.Loop() {
		if _, drop := names.Respond(q, z); drop {
			b.Fatal("unexpected drop")
		}
	}
}

// BenchmarkRespond_Malformed measures the cheapest rejection. Compared against
// the hit above, it says how much work a peer can make the responder do with
// input it never has to get right.
func BenchmarkRespond_Malformed(b *testing.B) {
	z := benchZone(b)
	junk := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	b.ReportAllocs()
	for b.Loop() {
		names.Respond(junk, z)
	}
}
