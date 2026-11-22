package pairstate

import (
	"net/netip"
	"sync"
	"time"
)

// AuthorizedHolder reads authorized_clients for every handshake and keeps the
// last set that loaded. It is safe for concurrent use.
//
// Stub: not implemented yet.
type AuthorizedHolder struct {
	mu sync.Mutex
}

// StaleEvent reports that the holder is serving its last good list because
// the file was rejected, or (Recovered) that the file is accepted again.
type StaleEvent struct {
	Path      string
	Err       error     // the rejection; nil for a recovery event
	Serving   int       // entries in the last-known-good set still being enforced
	LoadedAt  time.Time // when that set was loaded
	Recovered bool      // true for the single "file accepted again" event
}

// holderOpts are the holder's injectable dependencies.
type holderOpts struct {
	now func() time.Time
}

// defaultHolderOpts returns the production dependencies.
func defaultHolderOpts() holderOpts { return holderOpts{} }

// OpenAuthorized loads path once (cold start). Stub: not implemented yet.
func OpenAuthorized(path string, onStale func(StaleEvent)) (*AuthorizedHolder, error) {
	return openAuthorizedWith(defaultHolderOpts(), path, onStale)
}

// openAuthorizedWith is OpenAuthorized with injectable dependencies.
func openAuthorizedWith(o holderOpts, path string, onStale func(StaleEvent)) (*AuthorizedHolder, error) {
	return &AuthorizedHolder{}, nil
}

// Entries re-reads the file and returns the entries now enforced. Stub.
func (h *AuthorizedHolder) Entries() []Entry { return nil }

// Source returns an identity.AllowedSource-shaped func. Stub.
func (h *AuthorizedHolder) Source(cfgList, flagList []string) func() map[string]struct{} {
	return func() map[string]struct{} { return map[string]struct{}{} }
}

// AuthorizedPersister adapts the pairing handler's Persister and Confirmer
// to authorized_clients. Stub: not implemented yet.
type AuthorizedPersister struct {
	Path string
	Now  func() time.Time
}

// Persist records pin as unconfirmed. Stub.
func (p *AuthorizedPersister) Persist(pin, label string, from netip.AddrPort) error { return nil }

// Confirm marks pin confirmed. Stub.
func (p *AuthorizedPersister) Confirm(pin string) error { return nil }
