package fwd

// registry_test.go unit-tests the shutdown registry directly (internal
// package, unexported API) so the accept-vs-shutdown race fix (F10) is
// provable with no timing dependency at all, complementing fwd_test.go's
// black-box, real-goroutine TestForwarder_AcceptVsShutdownRace scenario.
// TestMain (goleak) lives in the external fwd_test package; this file
// intentionally does not redefine it.

import (
	"net"
	"testing"
)

// fakeConn is a minimal net.Conn stub whose only observable behavior is
// whether Close was called — enough for registry tests, which never read or
// write through these connections.
type fakeConn struct {
	net.Conn
	closed bool
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

func TestRegistry_RegisterAfterClose_FailsAndCallerMustReset(t *testing.T) {
	r := newRegistry()
	r.closeAll() // shutdown has already happened

	local := &fakeConn{}
	id, ok := r.register(local)
	if ok {
		t.Fatalf("register succeeded after closeAll (id=%d); want ok=false so the "+
			"caller resets local itself and never calls Attach", id)
	}
	if got := r.size(); got != 0 {
		t.Errorf("size = %d, want 0 (a failed registration must not be added)", got)
	}
}

func TestRegistry_RegisterBeforeClose_SweptByCloseAll(t *testing.T) {
	r := newRegistry()
	local := &fakeConn{}
	id, ok := r.register(local)
	if !ok {
		t.Fatal("register before closeAll should succeed")
	}
	if got := r.size(); got != 1 {
		t.Fatalf("size = %d, want 1", got)
	}

	r.closeAll()

	if !local.closed {
		t.Error("closeAll did not reset the already-registered local leg")
	}
	// closeAll deliberately leaves the entry in the map — its owning
	// goroutine deregisters itself once its own abort/splice path returns —
	// so size stays 1 until deregister is called.
	if got := r.size(); got != 1 {
		t.Errorf("size = %d, want 1 (closeAll must not itself remove entries)", got)
	}
	r.deregister(id)
	if got := r.size(); got != 0 {
		t.Errorf("size = %d, want 0 after deregister", got)
	}
}

func TestRegistry_SetRemoteAfterClose_Fails(t *testing.T) {
	r := newRegistry()
	local := &fakeConn{}
	id, ok := r.register(local)
	if !ok {
		t.Fatal("register should succeed before closeAll")
	}
	r.closeAll()

	remote := &fakeConn{}
	if r.setRemote(id, remote) {
		t.Fatal("setRemote succeeded after closeAll; want false so the caller " +
			"resets remote itself and never calls Pipe")
	}
}

func TestRegistry_SetRemoteBeforeClose_Succeeds(t *testing.T) {
	r := newRegistry()
	local := &fakeConn{}
	id, _ := r.register(local)

	remote := &fakeConn{}
	if !r.setRemote(id, remote) {
		t.Fatal("setRemote should succeed before closeAll")
	}
}

func TestRegistry_DeregisterIsIdempotent(t *testing.T) {
	r := newRegistry()
	local := &fakeConn{}
	id, _ := r.register(local)
	r.deregister(id)
	r.deregister(id) // must not panic
	if got := r.size(); got != 0 {
		t.Errorf("size = %d, want 0", got)
	}
}
