package router

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fillVhosts publishes names until the table holds as many as it will, and
// returns the last name it managed to publish.
//
// It counts up to a ceiling far above the bound so a broken check cannot turn
// this into a loop that runs forever: a test that hangs reports nothing, which
// is the one outcome worse than a failure.
func fillVhosts(t *testing.T, r *Router) string {
	t.Helper()
	var last string
	for i := 0; i < 10*MaxVhosts; i++ {
		host := fmt.Sprintf("svc%d.server1.internal", i)
		err := r.AddVhost(host, 3000+i%1000)
		if err == nil {
			last = host
			continue
		}
		if !errors.Is(err, ErrVhostLimit) {
			t.Fatalf("AddVhost(%q) failed for a reason other than the bound: %v", host, err)
		}
		return last
	}
	t.Fatalf("the table accepted %d names without ever reporting a bound", 10*MaxVhosts)
	return ""
}

// TestAddVhost_APublishPastTheBoundIsRefused is the whole point of the bound. A
// caller allowed to publish could otherwise publish for as long as the process
// lived: being authenticated decides who may ask, and nothing decided how often.
//
// The refusal is checked by its condition rather than its words, because
// everything downstream — the reply the caller gets, the reason written to the
// log, the sentence an operator reads — is chosen by asking which condition this
// is, not by reading the sentence.
func TestAddVhost_APublishPastTheBoundIsRefused(t *testing.T) {
	r := mustVhostRouter(t)
	fillVhosts(t, r)

	if got := len(r.Vhosts()); got != MaxVhosts {
		t.Fatalf("the table holds %d names at the bound, want %d", got, MaxVhosts)
	}
	err := r.AddVhost("one-too-many.server1.internal", 3000)
	if !errors.Is(err, ErrVhostLimit) {
		t.Fatalf("publishing past the bound returned %v, want ErrVhostLimit", err)
	}
	if got := len(r.Vhosts()); got != MaxVhosts {
		t.Errorf("a refused publish still changed the table: it now holds %d names, want %d", got, MaxVhosts)
	}
}

// TestAddVhost_ARepeatAtTheBoundStillSucceeds is the control that proves the
// bound is asked about after the repeat and not before it.
//
// Repeating an identical publish is what a caller does when a reply may have
// been lost, and it adds no entry — so a full table has no reason to refuse it,
// and refusing would turn a request that already succeeded into a failure the
// caller cannot resolve. The two checks agree about every request except this
// one, which is why nothing else can tell them apart.
func TestAddVhost_ARepeatAtTheBoundStillSucceeds(t *testing.T) {
	r := mustVhostRouter(t)
	last := fillVhosts(t, r)
	if last == "" {
		t.Fatal("nothing was published, so there is no repeat to make")
	}
	before := r.Vhosts()

	// Deliberately the same name AND the same address as the entry that is
	// already there: anything else is a takeover attempt rather than a repeat.
	rt, ok := r.vhosts.resolve(last)
	if !ok {
		t.Fatalf("%q does not resolve, so the repeat below would not be one", last)
	}
	port, err := strconv.Atoi(rt.raw[strings.LastIndex(rt.raw, ":")+1:])
	if err != nil {
		t.Fatalf("cannot read the port back out of %q: %v", rt.raw, err)
	}

	if err := r.AddVhost(last, port); err != nil {
		t.Fatalf("repeating an identical publish against a full table was refused: %v — "+
			"the bound must be asked about after the repeat, or a caller retrying a request "+
			"that already succeeded is told it failed", err)
	}
	if got, want := len(r.Vhosts()), len(before); got != want {
		t.Errorf("the table grew from %d to %d names on a repeat", want, got)
	}
}

// TestAddVhost_ConfiguredNamesCountTowardsTheBound covers the arithmetic that
// decides when a caller is refused. The reply that lists names carries both
// kinds, so a bound that counted only one of them would not bound the thing it
// exists to bound.
//
// A pattern is used for the configured entry on purpose: it lives in a separate
// map from an exact name, so a count that read one map would pass every other
// test in this file and still be wrong.
func TestAddVhost_ConfiguredNamesCountTowardsTheBound(t *testing.T) {
	const configured = 3
	entries := map[string]string{
		"*.wild.server1.internal":   "tcp://127.0.0.1:9001",
		"*.other.server1.internal":  "tcp://127.0.0.1:9002",
		"exact.thing.server1.local": "tcp://127.0.0.1:9003",
	}
	if len(entries) != configured {
		t.Fatalf("this test builds %d configured names but expects %d", len(entries), configured)
	}
	r, err := NewWithVhosts(nil, entries, nil)
	if err != nil {
		t.Fatalf("NewWithVhosts: %v", err)
	}

	fillVhosts(t, r)
	if got := len(r.Vhosts()); got != MaxVhosts {
		t.Fatalf("the table holds %d names in total, want %d — the operator's own names "+
			"are not being counted", got, MaxVhosts)
	}
}

// TestNewVhosts_AConfigurationLargerThanTheBoundIsRefusedAtStartup checks the
// half of the rule an operator meets rather than a caller.
//
// It is refused while somebody is watching the process start, which is the same
// posture the table already takes towards an address it cannot parse. The
// alternative is a configuration that loads and then refuses the first caller
// for a reason that has nothing to do with what they asked.
//
// Both numbers are named here, and that is deliberate: this message is read by
// the operator of this machine about their own file, so what this build holds is
// exactly what they need. The refusal that travels back over the network names
// neither.
func TestNewVhosts_AConfigurationLargerThanTheBoundIsRefusedAtStartup(t *testing.T) {
	tooMany := make(map[string]string, MaxVhosts+1)
	for i := 0; i < MaxVhosts+1; i++ {
		tooMany[fmt.Sprintf("cfg%d.server1.internal", i)] = "tcp://127.0.0.1:3000"
	}

	_, err := NewWithVhosts(nil, tooMany, nil)
	if !errors.Is(err, ErrVhostLimit) {
		t.Fatalf("a configuration of %d names was accepted (or refused for another reason): %v",
			MaxVhosts+1, err)
	}
	for _, want := range []string{strconv.Itoa(MaxVhosts + 1), strconv.Itoa(MaxVhosts)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot tell how far over "+
				"they are: %q", want, err.Error())
		}
	}

	// The boundary itself must load, or the number the message names would be
	// one an operator cannot actually use.
	exactly := make(map[string]string, MaxVhosts)
	for i := 0; i < MaxVhosts; i++ {
		exactly[fmt.Sprintf("cfg%d.server1.internal", i)] = "tcp://127.0.0.1:3000"
	}
	r, err := NewWithVhosts(nil, exactly, nil)
	if err != nil {
		t.Fatalf("a configuration of exactly %d names was refused: %v", MaxVhosts, err)
	}
	if got := len(r.Vhosts()); got != MaxVhosts {
		t.Errorf("the table holds %d of the %d configured names", got, MaxVhosts)
	}
}

// TestAddVhost_TheBoundRefusalCarriesNothingTheCallerWrote is a containment
// property, not a wording preference.
//
// This message does not stay here. It is passed to the caller as the text of an
// RPC failure and printed by the program that asked, so anything of the
// caller's inside it is text the caller placed in somebody else's terminal. The
// other refusals quote the name because they have to — an operator needs to know
// which entry is in the way — but nothing about a full table depends on the name
// that happened to arrive last.
func TestAddVhost_TheBoundRefusalCarriesNothingTheCallerWrote(t *testing.T) {
	r := mustVhostRouter(t)
	fillVhosts(t, r)

	const distinctive = "zzqqxx-a-name-nothing-else-would-produce.server1.internal"
	err := r.AddVhost(distinctive, 3000)
	if !errors.Is(err, ErrVhostLimit) {
		t.Fatalf("publishing past the bound returned %v, want ErrVhostLimit", err)
	}
	if strings.Contains(err.Error(), "zzqqxx") {
		t.Errorf("the refusal repeats the name the caller sent: %q", err.Error())
	}
	if got := err.Error(); got != ErrVhostLimit.Error() {
		t.Errorf("the refusal says %q, want exactly the condition and nothing else — "+
			"anything added here travels back to whoever asked", got)
	}
}
