package proto

// Benchmarks for the wire codec.
//
// Every stream pays this twice before a single payload byte moves: one header
// frame out, one response frame back. That sequence is mandatory, so the
// aggregate below is the number that describes what opening a stream costs, and
// the individual marshal and parse benchmarks are diagnostics for it rather than
// figures to read on their own.
//
// As with the naming parsers, the allocation columns are the stable ones. This
// codec is also the one place a dependency upgrade could silently change
// performance, since the encoding is provided by a third-party CBOR library, and
// an allocation count is what would show that.

import (
	"bytes"
	"testing"
)

func benchHeaderTCP() Header {
	return Header{
		Kind:   KindTCP,
		Target: "ssh",
		Meta:   map[string]string{"reqid": "01HQ8ZK3V9MW2N4P6R8T0Y2A4C"},
	}
}

func benchHeaderHTTP() Header {
	return Header{
		Kind: KindHTTP,
		Host: "grafana.server1.internal",
		Port: 3000,
		Meta: map[string]string{"reqid": "01HQ8ZK3V9MW2N4P6R8T0Y2A4C"},
	}
}

func BenchmarkHeaderMarshal_TCP(b *testing.B) {
	h := benchHeaderTCP()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHeaderMarshal_HTTP(b *testing.B) {
	h := benchHeaderHTTP()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseHeader_TCP(b *testing.B) {
	payload, err := benchHeaderTCP().Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := ParseHeader(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseHeader_HTTP(b *testing.B) {
	payload, err := benchHeaderHTTP().Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := ParseHeader(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResponseMarshal(b *testing.B) {
	r := Response{Status: StatusOK, Msg: ""}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseResponse(b *testing.B) {
	payload, err := Response{Status: StatusOK, Msg: ""}.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseResponse(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteFrame(b *testing.B) {
	payload, err := benchHeaderHTTP().Marshal()
	if err != nil {
		b.Fatal(err)
	}
	var buf bytes.Buffer
	buf.Grow(1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		buf.Reset()
		if err := WriteFrame(&buf, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadFrame(b *testing.B) {
	payload, err := benchHeaderHTTP().Marshal()
	if err != nil {
		b.Fatal(err)
	}
	var framed bytes.Buffer
	if err := WriteFrame(&framed, payload); err != nil {
		b.Fatal(err)
	}
	wire := framed.Bytes()
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		if _, err := ReadFrame(bytes.NewReader(wire)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRoundTrip_HeaderPlusResponse is the aggregate, and the one to watch.
// It is what every stream pays before carrying anything: marshal and frame a
// header, read it back, then marshal, frame and read a response. The protocol
// requires exactly this exchange, so a regression anywhere in the codec shows up
// here whether or not the individual benchmarks above make it obvious.
func BenchmarkRoundTrip_HeaderPlusResponse(b *testing.B) {
	h := benchHeaderHTTP()
	r := Response{Status: StatusOK, Msg: ""}
	var buf bytes.Buffer
	buf.Grow(1024)
	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()

		hp, err := h.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		if err := WriteFrame(&buf, hp); err != nil {
			b.Fatal(err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ParseHeader(got); err != nil {
			b.Fatal(err)
		}

		buf.Reset()
		rp, err := r.Marshal()
		if err != nil {
			b.Fatal(err)
		}
		if err := WriteFrame(&buf, rp); err != nil {
			b.Fatal(err)
		}
		gotR, err := ReadFrame(&buf)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ParseResponse(gotR); err != nil {
			b.Fatal(err)
		}
	}
}
