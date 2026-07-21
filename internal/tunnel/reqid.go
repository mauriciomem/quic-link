package tunnel

import (
	"crypto/rand"
	"encoding/hex"
)

// NewReqID generates a random 8-byte correlation identifier and returns it as
// a 16-character lowercase hex string. It is a trace/correlation aid for
// matching a client-side stream log entry to the corresponding agent-side
// entry across two hosts — NOT a security token, so a graceful fallback
// (empty string) on a crypto/rand failure is acceptable rather than crashing
// the data path.
func NewReqID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
