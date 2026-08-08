package tunnel

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mauriciomem/quic-link/internal/control"
	"github.com/mauriciomem/quic-link/internal/router"
)

// TestPublishError_SaysTheConditionExactlyOnce is the property this translation
// exists for. Both sides of the boundary name the same condition — one in the
// vocabulary a caller is answered in, one in the route table's own — so a
// message that carried both would say it twice, and an operator reading it would
// reasonably wonder whether two things went wrong.
//
// The cases below are the shapes the route table can actually produce, plus the
// ones it could produce after some later edit. A translation that reads the
// words of a message rather than its structure gets several of them wrong, and
// the wrong answers are not obviously wrong — they are the same sentence with
// something extra in it.
func TestPublishError_SaysTheConditionExactlyOnce(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error // the sentinel a caller should see
		// mayEchoRouter marks a case where the route table's own wording can
		// legitimately survive: it is inside the explanation rather than being
		// the condition. That happens when a caller chooses a name containing
		// it, which no translation can prevent and none should try to — the
		// alternative is editing what an operator is shown about their own
		// entry. What matters is that the CONDITION is stated once, which every
		// case asserts.
		mayEchoRouter bool
	}{
		{
			name: "an ordinary refusal",
			err:  fmt.Errorf("%w: %q is set in the agent's configuration", router.ErrVhostExists, "a.b"),
			want: control.ErrNameTaken,
		},
		{
			name: "a bare sentinel with nothing added",
			err:  router.ErrVhostExists,
			want: control.ErrNameTaken,
		},
		{
			// The route table always names the condition outermost, so this
			// shape does not occur today. It is here because a later edit could
			// wrap one, and the translation should carry the condition once
			// rather than tell a caller nothing.
			name:          "a sentinel wrapped by something else first",
			err:           fmt.Errorf("while publishing: %w", router.ErrVhostExists),
			want:          control.ErrNameTaken,
			mayEchoRouter: true,
		},
		{
			// A name containing the route table's own wording. It survives —
			// inside the quoted name, where it belongs — and the condition is
			// still stated once.
			name: "a refusal whose explanation quotes the condition",
			err: fmt.Errorf("%w: %q is a compiled-in default", router.ErrVhostExists,
				router.ErrVhostExists.Error()+": from a hostile name"),
			want:          control.ErrNameTaken,
			mayEchoRouter: true,
		},
		{
			name: "a rejected request",
			err:  fmt.Errorf("%w: port 0 is outside the usable range 1-65535", router.ErrVhostRejected),
			want: control.ErrNameRejected,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := publishError(c.err)
			if !errors.Is(got, c.want) {
				t.Fatalf("translated to %v, want it to carry %v", got, c.want)
			}
			// The condition must be named once and only once. Counting is the
			// assertion, because "contains" would pass on a message that said
			// it twice, which is the whole failure being prevented.
			condition := c.want.Error()
			if n := strings.Count(got.Error(), condition); n != 1 {
				t.Errorf("the message names %q %d times, want exactly once: %q", condition, n, got.Error())
			}
			// The route table's own wording must not be carried across AS the
			// condition — that is what produces one sentence naming the same
			// thing in two vocabularies. It is allowed to appear inside the
			// explanation, where it can only have come from a name the caller
			// chose.
			if !c.mayEchoRouter {
				prefix := c.want.Error() + ": " + router.ErrVhostExists.Error()
				if strings.HasPrefix(got.Error(), prefix) {
					t.Errorf("the message states the condition twice over: %q", got.Error())
				}
			}
		})
	}
}

// TestPublishError_KeepsTheExplanationAnOperatorNeeds guards the other
// direction. A translation that dropped everything except the condition would
// satisfy the test above and tell an operator nothing about which entry was in
// the way or what was wrong with the request.
func TestPublishError_KeepsTheExplanationAnOperatorNeeds(t *testing.T) {
	err := publishError(fmt.Errorf("%w: %q is set in the agent's configuration and points at %s",
		router.ErrVhostExists, "grafana.server1.internal", "tcp://127.0.0.1:3000"))

	for _, want := range []string{"grafana.server1.internal", "configuration", "tcp://127.0.0.1:3000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lost %q, which is what tells an operator what to do: %q", want, err.Error())
		}
	}
}

// TestPublishError_AnUnrecognizedFailureIsNotReshaped keeps the translation from
// claiming to understand something it does not. A failure with no known
// condition must pass through, so it reaches the layer that decides what an
// unrecognized failure means rather than being mislabelled here.
func TestPublishError_AnUnrecognizedFailureIsNotReshaped(t *testing.T) {
	original := errors.New("something nobody anticipated")
	got := publishError(original)
	if !errors.Is(got, original) {
		t.Errorf("an unrecognized failure was replaced rather than passed on: %v", got)
	}
	for _, sentinel := range []error{control.ErrNameTaken, control.ErrNameRejected} {
		if errors.Is(got, sentinel) {
			t.Errorf("an unrecognized failure was labelled %v", sentinel)
		}
	}
}
