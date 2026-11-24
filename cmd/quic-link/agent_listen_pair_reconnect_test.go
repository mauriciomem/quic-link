/**
 * @spec-handoff
 * @interface pairstate.OpenAuthorized(path, onStale) -> holder.Source(nil, nil) as the steady AllowedSource of identity.ListenTLSWithPairing; &pairstate.AuthorizedPersister{Path} as pairing.Serve's Persister and Confirmer
 * @behavior
 *   - Before pairing the joiner's key is refused on quic-link/1 (remote 0x12a): authorized_clients is empty
 *   - A test-only joiner pairs over pair1 through agentListenTransport + the routed listener + pairing.Serve; the persister appends `PIN state=unconfirmed # label="joiner" from=127.0.0.1:PORT at=...`, then Confirm promotes it to state=confirmed
 *   - The very next quic-link/1 handshake from the same key is admitted (the holder re-reads the file per handshake, no restart) and a data stream reaches the tunnel's TCP sink
 *   - Removing the line revokes: the next handshake is refused again; no stale-list event at any point
 *   - Every handshake goes through a QUIC Retry
 * @edge-cases
 *   - Nothing is wired into the agent; cmd changes are tests only
 * @see ../../internal/pairstate/holder.go ./agent_listen_pair_routing_test.go
 */
package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"go.uber.org/goleak"

	"github.com/mauriciomem/quic-link/internal/pairing"
	"github.com/mauriciomem/quic-link/internal/pairstate"
	"github.com/mauriciomem/quic-link/internal/transport"
)

// wantSteadyRefused asserts that a quic-link/1 dial was refused by the
// listener: either at dial, or (TLS 1.3 client auth) with remote 0x12a on
// the first exchange.
func wantSteadyRefused(t *testing.T, what string, c transport.Conn, err error) {
	t.Helper()
	if err == nil {
		err = tunnelToSink(c, []byte("must-not-arrive"))
		if err == nil {
			t.Errorf("%s: the steady session was admitted, want it refused", what)
			return
		}
	}
	var te *quic.TransportError
	if !errors.As(err, &te) || te.ErrorCode != 0x12a || !te.Remote {
		t.Errorf("%s: err = %v, want a remote TLS alert 0x12a (certificate refused)", what, err)
	}
}

func TestAgentListenTransport_PairThenReconnectSteady(t *testing.T) {
	// Registered first, so it runs after every other cleanup has closed the
	// listener, the transports and the tunnel server.
	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, ignore) })

	srvKey, _, srvPin, _ := newSeamKeys(t)
	_, joinKey, _, joinPin := newSeamKeys(t)
	path := filepath.Join(t.TempDir(), "authorized_clients")

	var (
		staleMu sync.Mutex
		stale   []pairstate.StaleEvent
	)
	holder, err := pairstate.OpenAuthorized(path, func(e pairstate.StaleEvent) {
		staleMu.Lock()
		defer staleMu.Unlock()
		stale = append(stale, e)
	})
	if err != nil {
		t.Fatalf("OpenAuthorized: %v", err)
	}
	per := &pairstate.AuthorizedPersister{Path: path}
	var _ pairing.Persister = per
	var _ pairing.Confirmer = per

	w, err := pairing.OpenWindow(srvPin, 0)
	if err != nil {
		t.Fatalf("OpenWindow: %v", err)
	}
	t.Cleanup(w.Close)
	blob, err := pairing.ParseBlob(w.Blob())
	if err != nil {
		t.Fatalf("ParseBlob: %v", err)
	}
	secret := blob.Secret()
	a := startRoutedAgentFrom(t, srvKey, srvPin, holder.Source(nil, nil), w, per)

	t.Run("before pairing the joiner is not authorized", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, joinKey, srvPin, transport.ALPN)
		wantSawRetry(t, retries)
		wantSteadyRefused(t, "steady dial before pairing", c, err)
	})

	t.Run("the joiner pairs and is persisted, then confirmed", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, joinKey, srvPin, seamPair1)
		if err != nil {
			t.Fatalf("joiner dial: %v", err)
		}
		wantSawRetry(t, retries)
		resp, err := joinOnce(c, secret[:], "joiner")
		if err != nil {
			t.Fatalf("pairing exchange: %v", err)
		}
		if resp.Status != pairing.StatusOK {
			t.Fatalf("valid proof answered %v, want ok", resp.Status)
		}

		// Confirm runs after the answer is written: wait for it.
		var res pairstate.LoadResult
		deadline := time.Now().Add(5 * time.Second)
		for {
			res, err = pairstate.LoadAuthorized(path)
			if err == nil && len(res.Entries) == 1 && res.Entries[0].State == pairstate.StateConfirmed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("authorized_clients = (%+v, %v), want one confirmed entry for the joiner", res, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		e := res.Entries[0]
		if e.Pin != joinPin {
			t.Errorf("persisted pin %q, want the joiner's %q", e.Pin, joinPin)
		}
		if !strings.HasPrefix(e.Comment, `label="joiner" from=127.0.0.1:`) || !strings.Contains(e.Comment, " at=") {
			t.Errorf("comment %q, want label=\"joiner\" from=127.0.0.1:PORT at=TIME", e.Comment)
		}
		if w.IsOpen() {
			t.Error("window still open after pairing")
		}
	})

	t.Run("the next steady handshake is admitted without a restart", func(t *testing.T) {
		c, retries, err := routedDial(t, a.addr, joinKey, srvPin, transport.ALPN)
		if err != nil {
			t.Fatalf("steady dial after pairing: %v", err)
		}
		wantSawRetry(t, retries)
		if err := tunnelToSink(c, []byte("after-pairing")); err != nil {
			t.Fatalf("steady session after pairing: %v", err)
		}
		select {
		case got := <-a.sinkCh:
			if !bytes.Equal(got, []byte("after-pairing")) {
				t.Errorf("sink got %q, want %q", got, "after-pairing")
			}
		case <-time.After(5 * time.Second):
			t.Error("sink never received the steady payload")
		}
	})

	t.Run("removing the line revokes the next handshake", func(t *testing.T) {
		if _, err := pairstate.RemoveAuthorized(path, joinPin[:8]); err != nil {
			t.Fatalf("RemoveAuthorized: %v", err)
		}
		c, retries, err := routedDial(t, a.addr, joinKey, srvPin, transport.ALPN)
		wantSawRetry(t, retries)
		wantSteadyRefused(t, "steady dial after revocation", c, err)
	})

	staleMu.Lock()
	if len(stale) != 0 {
		t.Errorf("stale-list events = %+v, want none", stale)
	}
	staleMu.Unlock()
	if got := a.handledProtos(); !slices.Equal(got, []string{seamPair1}) {
		t.Errorf("the pairing handler received %q, want exactly one pair1 connection", got)
	}
	if got := a.rec.seen(); slices.Contains(got, seamPair1) {
		t.Errorf("tunnel.Serve received %q: a pair1 connection must never reach it", got)
	}
}
