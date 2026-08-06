package edge

import (
	"github.com/mauriciomem/quic-link/internal/names"
)

// HTTPPeeker finds the destination of a plaintext HTTP request.
//
// It waits for the whole header block even once it has seen a host, because a
// second host further down is exactly the ambiguity that has to be refused, and
// stopping at the first one would be a way to hide it.
type HTTPPeeker struct{}

func (HTTPPeeker) kind() string { return "http" }

func (HTTPPeeker) name(buf []byte) (string, int, error) {
	end := names.HeaderEnd(buf)
	if end < 0 {
		return "", 0, nil // keep reading
	}
	host, err := names.HostFromRequest(buf[:end])
	if err != nil {
		return "", 0, err
	}
	return host, end, nil
}
