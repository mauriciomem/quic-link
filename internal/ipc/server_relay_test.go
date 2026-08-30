package ipc_test

// server_relay_test.go proves a PROPERTY across handleRPC's four live-relay
// cases (routes, vhosts, withdraw, expose): every one of them refuses an
// oversized reply with a named, non-zero-status error instead of a bare
// socket failure. A prior audit found the withdraw case missing this check
// while its three siblings had it — the defect that made this exact
// structural gap worth pinning as one table-driven property rather than
// four independent tests that could each regress on their own. This file
// also plugs the one relay case (vhosts) that had no dedicated frame-size
// test of its own before this one, alongside routes/withdraw/expose which
// each already had one.
//
// @spec-handoff
//
// Interface under test: ipc.Server's "routes"/"vhosts"/"withdraw"/"expose"
// RPC cases in handleRPC, via each corresponding Provider interface
// (RoutesProvider, VhostsProvider, WithdrawProvider, ExposeProvider).
//
// Expected behavior: when a provider's JSON-returning method answers with a
// body whose encoding exceeds the socket frame's carrying capacity once
// enveloped (maxFrameSize minus the CBOR envelope headroom), the client gets
// a *ipc.RoutesError naming the reply as too large and local — for every one
// of the four relay kinds, not just whichever one a past defect happened to
// surface in. A repliable-size body still succeeds and is returned verbatim,
// proving the bound does not fire on ordinary replies.
//
// Edge case exercised: this table drives all four relay kinds through the
// same two assertions (oversized refuses by name, repliable-size succeeds)
// so a fifth relay added later has an obvious row to add rather than a new
// test file to write from scratch.
//
// Pre-fix failure mode (withdraw, historically): an oversized body reached
// writeResponse unchecked; the underlying frame write refused internally and
// the caller's read failed with a bare EOF, carrying no *ipc.RoutesError at
// all, indistinguishable from a dead daemon.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/ipc"
)

// relayFrameSizeCase names one relay kind's provider wiring and the client
// call that exercises it, so the oversized/repliable pair below can drive
// all four through the same assertions.
type relayFrameSizeCase struct {
	name string
	// startServer wires body as the case's provider reply and returns a
	// listening socket path.
	startServer func(t *testing.T, body []byte) string
	// invoke calls the corresponding Client method against sock.
	invoke func(sock string) ([]byte, error)
}

// hugeJSONField is comfortably past the frame limit regardless of the exact
// envelope headroom reserved around it, so these cases do not depend on that
// constant's exact value.
const hugeFieldSize = 200_000

func relayFrameSizeCases() []relayFrameSizeCase {
	return []relayFrameSizeCase{
		{
			name: "routes",
			startServer: func(t *testing.T, body []byte) string {
				stub := newStubRoutes()
				stub.body = body
				sock, _ := startTestServerWithRoutes(t, &stubStatus{data: []byte(`{}`)}, &stubPool{}, stub)
				return sock
			},
			invoke: func(sock string) ([]byte, error) {
				return ipc.NewClient(sock).RoutesJSON("srv1")
			},
		},
		{
			name: "vhosts",
			startServer: func(t *testing.T, body []byte) string {
				return startTestServerWithVhosts(t, &frameSizeVhosts{body: body})
			},
			invoke: func(sock string) ([]byte, error) {
				return ipc.NewClient(sock).VhostsJSON("srv1")
			},
		},
		{
			name: "withdraw",
			startServer: func(t *testing.T, body []byte) string {
				return startTestServerWithWithdrawProvider(t, &stubWithdraw{body: body})
			},
			invoke: func(sock string) ([]byte, error) {
				return ipc.NewClient(sock).WithdrawJSON("srv1", "n.srv1.internal")
			},
		},
		{
			name: "expose",
			startServer: func(t *testing.T, body []byte) string {
				return startTestServerWithExpose(t, &stubExpose{body: body})
			},
			invoke: func(sock string) ([]byte, error) {
				return ipc.NewClient(sock).ExposeJSON("srv1", "grafana.srv1.internal", 3000)
			},
		},
	}
}

// frameSizeVhosts is a VhostsProvider returning a fixed body, mirroring
// stubExpose/stubWithdraw's shape for the one relay kind that did not
// already have one.
type frameSizeVhosts struct{ body []byte }

func (v *frameSizeVhosts) VhostsJSON(context.Context, string) ([]byte, error) {
	return v.body, nil
}

// TestRelayFrameBound_OversizedReplyIsANamedRefusalOnEveryRelayKind is the
// property: every one of the four relay kinds refuses an oversized reply by
// name rather than leaving the caller with a bare socket error.
func TestRelayFrameBound_OversizedReplyIsANamedRefusalOnEveryRelayKind(t *testing.T) {
	for _, c := range relayFrameSizeCases() {
		t.Run(c.name, func(t *testing.T) {
			huge := []byte(`{"schema":1,"server":"srv1","field":"` + strings.Repeat("a", hugeFieldSize) + `"}`)
			sock := c.startServer(t, huge)

			_, err := c.invoke(sock)
			if err == nil {
				t.Fatal("an oversized reply was relayed as a success")
			}
			var re *ipc.RoutesError
			if !errors.As(err, &re) {
				t.Fatalf("got a bare transport error rather than a named refusal: %v", err)
			}
			// The four relays word the refusal differently (a route "table",
			// a vhosts "name" listing, a withdrawal "reply", an expose
			// "reply" are not the same noun), but every one of them must
			// name the limit as local — the part of the message that keeps
			// an operator from going to look for the problem on the agent.
			if !strings.Contains(re.Msg, "local") {
				t.Errorf("refusal does not say the limit is a local one: %q", re.Msg)
			}
		})
	}
}

// TestRelayFrameBound_RepliableSizeStillSucceedsOnEveryRelayKind is the
// companion property: the bound above does not fire on an ordinary,
// well-within-frame reply. Without this, the oversized test above could
// pass because every relay refuses everything, not because the bound is
// correctly sized.
func TestRelayFrameBound_RepliableSizeStillSucceedsOnEveryRelayKind(t *testing.T) {
	for _, c := range relayFrameSizeCases() {
		t.Run(c.name, func(t *testing.T) {
			body := []byte(`{"schema":1,"server":"srv1","field":"ordinary"}`)
			sock := c.startServer(t, body)

			got, err := c.invoke(sock)
			if err != nil {
				t.Fatalf("relay: %v", err)
			}
			if string(got) != string(body) {
				t.Errorf("body = %s, want %s", got, body)
			}
		})
	}
}
