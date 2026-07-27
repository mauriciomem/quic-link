package daemon

import (
	"time"

	"github.com/mauriciomem/quic-link/internal/identity"
)

// readIdentityMeta reads the .meta sidecar for keyPath using the identity
// package. This thin bridge keeps the identity import isolated so it is easy
// to replace in tests.
func readIdentityMeta(keyPath string) (time.Time, bool, error) {
	return identity.ReadMeta(keyPath)
}
