package control

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestSingleConnListener verifies the listener yields its one conn once, then
// blocks on subsequent Accepts until Close returns net.ErrClosed.
func TestSingleConnListener(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ln := NewSingleConnListener(c1)

	got, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if got != c1 {
		t.Fatal("first Accept returned a different conn")
	}

	done := make(chan error, 1)
	go func() {
		_, e := ln.Accept()
		done <- e
	}()

	select {
	case <-done:
		t.Fatal("second Accept returned before Close")
	case <-time.After(100 * time.Millisecond):
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case e := <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("second Accept: want net.ErrClosed, got %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("second Accept did not return after Close")
	}
}
