package fwd

import (
	"net"
	"sync"

	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// inflightEntry holds the two legs of one accepted-but-not-yet-finished
// forward: the locally accepted TCP connection, and the connection obtained
// from Attacher.Attach. remote is nil until the attach completes — an entry
// is registered as soon as the local connection is accepted, before Attach is
// even called, so the registration window is as small as possible.
type inflightEntry struct {
	local  net.Conn
	remote net.Conn
}

// registry tracks every forward currently accepted but not yet fully torn
// down, so that shutdown can reset every open leg immediately instead of
// waiting for each splice to notice on its own.
//
// fwd has no single shared connection whose closure would cascade into every
// in-flight forward the way the daemon's one pooled QUIC connection does for
// its convenience-port edges: every accepted local connection results in an
// independent attach, each with its own socket connection to the daemon.
// This registry is the substitute kill switch that behavior needs.
//
// Registration and the "are we shutting down" check share one mutex so that a
// connection accepted in the last instant before shutdown cannot slip past
// the reset sweep: it either registers before closeAll runs — and is reset by
// the sweep — or register returns false because closed is already true, and
// the caller resets the connection on the spot without ever calling Attach.
// This is a deliberately simple design: register optimistically and then
// discovering "should I still be running" after the fact would reopen the
// exact race this exists to close.
type registry struct {
	mu      sync.Mutex
	closed  bool
	entries map[uint64]*inflightEntry
	nextID  uint64
}

func newRegistry() *registry {
	return &registry{entries: make(map[uint64]*inflightEntry)}
}

// register adds a new entry holding only the local leg — Attach has not been
// called yet. It returns the entry's id and true, or (0, false) if the
// registry has already begun shutting down. On false the caller must reset
// local itself immediately and must not proceed to call Attach at all.
func (r *registry) register(local net.Conn) (id uint64, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, false
	}
	r.nextID++
	id = r.nextID
	r.entries[id] = &inflightEntry{local: local}
	return id, true
}

// setRemote attaches the remote leg to an already-registered entry once
// Attach succeeds. It returns false if the registry has closed in the
// meantime: closeAll already reset the local leg for this entry, and the
// caller must reset remote itself and must never call Pipe on a connection
// the shutdown sweep has already torn down half of.
func (r *registry) setRemote(id uint64, remote net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	e, ok := r.entries[id]
	if !ok {
		return false
	}
	e.remote = remote
	return true
}

// deregister removes an entry once its splice (or its abort path) has fully
// ended. Safe to call more than once for the same id, and safe to call after
// closeAll has already run.
func (r *registry) deregister(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, id)
}

// size reports the number of entries currently tracked. Exported (via
// Forwarder.RegistrySize) so tests can assert shutdown completeness directly
// by observing the count reach zero, instead of inferring it from elapsed
// wall-clock time.
func (r *registry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// closeAll marks the registry closed — no further register calls will
// succeed — and resets every currently-tracked entry's legs immediately.
// Entries are intentionally left in the map: their owning goroutines
// deregister themselves once Pipe (or the abort path in handleConn) returns,
// which is what lets RegistrySize converge to zero as the true measure of
// shutdown completeness rather than this function's own return meaning
// "done".
func (r *registry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, e := range r.entries {
		if e.local != nil {
			tunnel.ResetConn(e.local)
		}
		if e.remote != nil {
			tunnel.ResetConn(e.remote)
		}
	}
}
