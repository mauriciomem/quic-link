package edge

import (
	"strings"
	"testing"
)

func TestHTTPPeeker_WaitsForTheWholeHeaderBlock(t *testing.T) {
	p := HTTPPeeker{}
	partial := []byte("GET / HTTP/1.1\r\nHost: a.internal\r\n")
	host, n, err := p.name(partial)
	if err != nil || n != 0 || host != "" {
		t.Fatalf("an unfinished header block must ask for more: got (%q,%d,%v)", host, n, err)
	}

	// Finishing it reveals a second host that the partial read could not see.
	full := []byte("GET / HTTP/1.1\r\nHost: a.internal\r\nHost: b.internal\r\n\r\n")
	if _, _, err := p.name(full); err == nil {
		t.Fatal("a second host must be refused; stopping at the first would hide it")
	}
}

func TestHTTPPeeker_ConsumesExactlyTheHeaderBlock(t *testing.T) {
	req := "POST /x HTTP/1.1\r\nHost: a.internal\r\nContent-Length: 5\r\n\r\nhello"
	host, n, err := HTTPPeeker{}.name([]byte(req))
	if err != nil {
		t.Fatal(err)
	}
	if host != "a.internal" {
		t.Errorf("host = %q", host)
	}
	if want := strings.Index(req, "hello"); n != want {
		t.Errorf("consumed %d bytes, want %d — the body must be left to stream", n, want)
	}
}
