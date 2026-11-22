package pairstate

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// staleRepeat is how long the holder waits before reporting the same
// rejection again.
const staleRepeat = 60 * time.Second

// AuthorizedHolder reads authorized_clients for every handshake and keeps the
// last set that loaded. It is safe for concurrent use.
//
// Each Entries call reads the file under the holder's lock, so concurrent
// callers are serialized; the file is small (at most 1 MiB) and every caller
// is a handshake that has already passed a QUIC Retry. A read that succeeds,
// including a missing file (no pins), replaces the enforced set, so a
// revoked line stops being accepted on the next handshake. A read that is
// rejected, for any reason, keeps the last good set and is reported through
// onStale.
type AuthorizedHolder struct {
	path    string
	now     func() time.Time
	onStale func(StaleEvent)

	mu        sync.Mutex
	lkg       []Entry   // last-known-good entries
	lkgAt     time.Time // when lkg was loaded
	stale     bool      // the last read was rejected
	lastCause string    // Err text of the last stale event; "" after a good read
	lastEvent time.Time // when that event was emitted
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
func defaultHolderOpts() holderOpts { return holderOpts{now: time.Now} }

// OpenAuthorized loads path once (cold start), with no earlier set to fall
// back to. A missing file or directory is an empty holder. A malformed or
// oversize file is an error matching ErrColdStart and ErrMalformed; an
// unsafe or unclean path is the ErrUnsafePath error, without ErrColdStart;
// any other error is returned as is.
//
// After a successful open, a rejected read keeps the last good set and calls
// onStale (which may be nil): once per cause, again for the same cause once
// 60 s have passed since it was last reported, and once with Recovered set
// when the file is accepted again. onStale is called after the holder's lock
// is released, on the caller's goroutine, so it may call Entries but must
// not block.
func OpenAuthorized(path string, onStale func(StaleEvent)) (*AuthorizedHolder, error) {
	return openAuthorizedWith(defaultHolderOpts(), path, onStale)
}

// openAuthorizedWith is OpenAuthorized with injectable dependencies.
func openAuthorizedWith(o holderOpts, path string, onStale func(StaleEvent)) (*AuthorizedHolder, error) {
	res, err := LoadAuthorizedAtStart(path)
	if err != nil {
		return nil, err
	}
	return &AuthorizedHolder{
		path:    path,
		now:     o.now,
		onStale: onStale,
		lkg:     res.Entries,
		lkgAt:   o.now(),
	}, nil
}

// Entries re-reads the file and returns the entries now enforced: the file's
// entries if it loaded, otherwise the last set that did. The caller owns the
// returned slice.
func (h *AuthorizedHolder) Entries() []Entry {
	h.mu.Lock()
	ev, emit := h.reload()
	out := slices.Clone(h.lkg)
	h.mu.Unlock()
	if emit && h.onStale != nil {
		h.onStale(ev)
	}
	return out
}

// reload reads the file and updates the holder. It reports the event to emit,
// if any. h.mu must be held.
func (h *AuthorizedHolder) reload() (StaleEvent, bool) {
	res, err := LoadAuthorized(h.path)
	now := h.now()
	if err == nil {
		h.lkg, h.lkgAt = res.Entries, now
		if !h.stale {
			return StaleEvent{}, false
		}
		h.stale, h.lastCause, h.lastEvent = false, "", time.Time{}
		return StaleEvent{Path: h.path, Serving: len(h.lkg), LoadedAt: h.lkgAt, Recovered: true}, true
	}
	h.stale = true
	cause := err.Error()
	if cause == h.lastCause && now.Sub(h.lastEvent) < staleRepeat {
		return StaleEvent{}, false
	}
	h.lastCause, h.lastEvent = cause, now
	return StaleEvent{
		Path:     h.path,
		Err:      err,
		Serving:  len(h.lkg),
		LoadedAt: h.lkgAt,
	}, true
}

// Source returns an identity.AllowedSource-shaped func computing
// EffectiveAuthorized(cfgList, flagList, h.Entries()) on every call, as a new
// map the caller may keep. With a non-empty flagList the file is never read,
// since flags replace it. The lists are copied.
func (h *AuthorizedHolder) Source(cfgList, flagList []string) func() map[string]struct{} {
	cfg, flags := slices.Clone(cfgList), slices.Clone(flagList)
	if len(flags) > 0 {
		return func() map[string]struct{} { return EffectiveAuthorized(nil, flags, nil) }
	}
	return func() map[string]struct{} { return EffectiveAuthorized(cfg, nil, h.Entries()) }
}

// AuthorizedPersister adapts the pairing handler's Persister and Confirmer
// to authorized_clients at Path. Now is the clock for the at= stamp; nil
// means time.Now.
type AuthorizedPersister struct {
	Path string
	Now  func() time.Time
}

// Persist appends pin as
// `PIN state=unconfirmed # label="LABEL" from=ADDR:PORT at=RFC3339` (see
// AppendAuthorized). A pin already present is left as it is, so a confirmed
// entry is never downgraded.
func (p *AuthorizedPersister) Persist(pin, label string, from netip.AddrPort) error {
	now := p.Now
	if now == nil {
		now = time.Now
	}
	// %+q keeps the comment printable ASCII whatever the label holds.
	comment := fmt.Sprintf("label=%+q from=%s at=%s", label, from, now().Format(time.RFC3339))
	_, err := AppendAuthorized(p.Path, Entry{Pin: pin, State: StateUnconfirmed, Comment: comment})
	return err
}

// Confirm marks pin confirmed (see PromoteAuthorized).
func (p *AuthorizedPersister) Confirm(pin string) error {
	return PromoteAuthorized(p.Path, pin)
}
