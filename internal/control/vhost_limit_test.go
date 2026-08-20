package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// refusingPublisher stands in for an agent whose name table is already holding
// as many names as it will.
type refusingPublisher struct{ err error }

func (p refusingPublisher) AddVhost(string, int) error { return p.err }

// TestPublishStatus_AFullTableIsNotReportedAsADefect pins the code a caller
// gets back.
//
// Falling through to the arm for an unrecognized failure would report it as an
// internal error, which says the agent went wrong. Nothing went wrong: the
// request was well formed and there was no room for it. The distinction decides
// what the operator on the other end is eventually told to do, because every
// layer above chooses its sentence from this code.
func TestPublishStatus_AFullTableIsNotReportedAsADefect(t *testing.T) {
	got := publishStatus(ErrNameLimit)
	if code := status.Code(got); code != codes.ResourceExhausted {
		t.Fatalf("a full table was reported as %v, want %v", code, codes.ResourceExhausted)
	}
	if !strings.Contains(status.Convert(got).Message(), "as many published names") {
		t.Errorf("the message does not say what the trouble is: %q", status.Convert(got).Message())
	}

	// The condition has to be recognized through a wrapping layer too, because
	// that is the shape it actually arrives in: the boundary that translates
	// the route table's errors wraps this sentinel rather than returning it.
	wrapped := publishStatus(fmt.Errorf("%w: while publishing", ErrNameLimit))
	if code := status.Code(wrapped); code != codes.ResourceExhausted {
		t.Errorf("a wrapped full-table error was reported as %v, want %v", code, codes.ResourceExhausted)
	}

	// And a failure nobody classified must NOT get the specific answer, or the
	// answer says nothing.
	unknown := publishStatus(errors.New("something nobody anticipated"))
	if code := status.Code(unknown); code != codes.Internal {
		t.Errorf("an unrecognized failure was reported as %v, want %v", code, codes.Internal)
	}
}

// TestPublishReason_AFullTableHasItsOwnWords covers the log side of the same
// refusal. The reasons are a fixed vocabulary this program owns, so an operator
// reading the audit trail can tell a table with no room from a name already in
// use without matching on text a caller had any part in choosing.
func TestPublishReason_AFullTableHasItsOwnWords(t *testing.T) {
	got := publishReason(ErrNameLimit)
	if got == publishReason(errors.New("something nobody anticipated")) {
		t.Fatal("a full table is recorded with the same reason as a failure nobody recognized, " +
			"so the audit trail cannot tell them apart")
	}
	if !strings.Contains(got, "as many names") {
		t.Errorf("the recorded reason does not say the table is full: %q", got)
	}
}

// TestAddVhost_AFullTableIsRefusedAndRecordedWithTheName drives the handler
// itself, because the code a caller sees and the line an operator finds
// afterwards are produced by two separate pieces of code on the same path.
//
// A refusal leaves nothing behind: it changed no state, so if it is not written
// down at the moment it happens there is nothing to notice it by later. A
// caller looping until the table filled is exactly the situation an operator
// would want to find in the log, and the name is what tells them who was asking
// for what.
func TestAddVhost_AFullTableIsRefusedAndRecordedWithTheName(t *testing.T) {
	const host = "one-too-many.server1.internal"

	records := make(chan slog.Record, 8)
	prev := slog.Default()
	slog.SetDefault(slog.New(recordCollector{out: records}))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := server{
		peer:   PeerIdentity{Pin: "abcdefghijklmnop"},
		policy: MutationPolicy{AllowMutation: true},
		names:  refusingPublisher{err: ErrNameLimit},
	}
	_, err := srv.AddVhost(context.Background(), &controlpb.AddVhostRequest{Host: host, Port: 3000})
	if code := status.Code(err); code != codes.ResourceExhausted {
		t.Fatalf("the handler answered %v, want %v", code, codes.ResourceExhausted)
	}

	// A bounded wait, then an assertion on what arrived. Waiting for a record
	// that never comes has to end in a failure that names the problem, not in a
	// test that simply never finishes.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-records:
			if r.Message != "route mutation refused" {
				continue
			}
			if r.Level != slog.LevelWarn {
				t.Errorf("the refusal was recorded at %v, want WARN", r.Level)
			}
			attrs := map[string]string{}
			r.Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = a.Value.String()
				return true
			})
			if attrs["name"] != host {
				t.Errorf("the record names %q, want the name that was asked for, %q", attrs["name"], host)
			}
			if !strings.Contains(attrs["reason"], "as many names") {
				t.Errorf("the record does not say the table was full: %q", attrs["reason"])
			}
			return
		case <-deadline:
			t.Fatal("a publish refused for want of room was recorded nowhere. A refusal changes " +
				"nothing, so there is no state left over to notice it by — the log line is the " +
				"only record that anyone tried.")
		}
	}
}
