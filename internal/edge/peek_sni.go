package edge

import (
	"github.com/mauriciomem/quic-link/internal/names"
)

// SNIPeeker finds the destination of a TLS connection from the name the client
// asks for as it opens the handshake.
//
// Nothing is decrypted and nothing is answered: the bytes read are passed on
// unchanged, so the handshake completes between the client and the service with
// this in the middle of neither end's trust.
type SNIPeeker struct{}

func (SNIPeeker) kind() string { return "https" }

func (SNIPeeker) name(buf []byte) (string, int, error) {
	host, need, err := names.SNIFromClientHello(buf)
	if err != nil {
		return "", 0, err
	}
	if need {
		return "", 0, nil
	}
	// Everything read so far is part of the client's handshake and is handed
	// on; the name was found by looking, not by consuming.
	return host, len(buf), nil
}
