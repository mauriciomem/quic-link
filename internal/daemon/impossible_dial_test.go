package daemon_test

// A daemon told to reach an address it could never reach used to say it was
// connecting, and go on saying it for as long as it ran. These tests separate
// the two things that can be wrong with such an address, because they deserve
// opposite treatment.
//
// An address that is wrong on its face — no port, or a family the outgoing
// socket cannot carry — can never start working, so the daemon refuses it and
// stops. An address that merely fails right now — a name not in DNS yet, a host
// switched off — must keep being retried, because a daemon that gives up on
// those turns a short outage into one that needs a person. What changes for the
// second kind is only that the status stops claiming "connecting" and nothing
// else: it now also says what went wrong.

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mauriciomem/quic-link/internal/config"
	"github.com/mauriciomem/quic-link/internal/daemon"
	"github.com/mauriciomem/quic-link/internal/transport"
	"github.com/mauriciomem/quic-link/internal/transport/mem"
)

// TestPoolRefusesAnAddressItCouldNeverDial covers the addresses that can never
// work. Building the pool must fail, and the failure must be reported as a
// configuration problem so the process exits with the code reserved for one.
func TestPoolRefusesAnAddressItCouldNeverDial(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"unparseable", "this is not an address at all"},
		{"no port", "192.0.2.10"},
		{"port with no host", ":7443"},
	}

	for _, tc := range cases {
		hub := mem.NewHub()
		cfg := config.Defaults()
		cfg.Servers = map[string]config.Server{"web": {Addr: tc.addr}}

		ctx, cancel := context.WithCancel(context.Background())
		pool, err := daemon.NewRealPool(
			ctx, cfg,
			func(_ string, _ config.Server) (transport.Transport, error) {
				return hub.Transport("refused:1"), nil
			},
			ceilingPolicy(), daemon.WallClock{}, nil,
		)
		if err == nil {
			pool.Close()
			cancel()
			t.Errorf("%s: building the pool with %q succeeded; an address that can never be "+
				"dialled must be refused rather than retried forever", tc.name, tc.addr)
			continue
		}
		cancel()

		if !strings.Contains(err.Error(), "invalid configuration") {
			t.Errorf("%s: refusal does not report itself as a configuration problem, so it "+
				"would not reach the exit code reserved for one: %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), "web") {
			t.Errorf("%s: refusal does not name the server: %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.addr) {
			t.Errorf("%s: refusal does not quote the address: %v", tc.name, err)
		}
	}
}

// TestRefusingAnAddressStartsNoRetryLoop is the half that proves the refusal
// happens early enough to matter. Refusing after the loop had started would
// leave a goroutine dialling an address the daemon has already rejected.
//
// The check is a count taken after a pause, not a wait for something to happen.
// Waiting for an event that should never arrive cannot fail; it can only run out
// of time, and a test that can only time out reports a stall rather than the
// thing it was written to detect.
func TestRefusingAnAddressStartsNoRetryLoop(t *testing.T) {
	hub := mem.NewHub()
	var dials atomic.Int64

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"web": {Addr: "this is not an address at all"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			dials.Add(1)
			return hub.Transport("refused:1"), nil
		},
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err == nil {
		pool.Close()
		t.Fatal("the pool accepted an address it can never dial")
	}

	transportsBuilt := dials.Load()
	time.Sleep(250 * time.Millisecond)

	if got := dials.Load(); got != transportsBuilt {
		t.Errorf("transports were still being built %d→%d after the address was refused; "+
			"the refusal came too late and a retry loop is running for a rejected server",
			transportsBuilt, got)
	}
}

// TestAnAddressThatMerelyFailsKeepsBeingRetried is the guard on the other half
// of the rule, and the more important one. A name that does not resolve is
// indistinguishable from a name whose DNS is briefly down, so the daemon must
// start and keep trying. If this test ever fails, a short outage has become a
// daemon that will not boot.
func TestAnAddressThatMerelyFailsKeepsBeingRetried(t *testing.T) {
	hub := mem.NewHub()
	tr := &countingDeadTransport{inner: hub.Transport("nothing-here:1")}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"web": {Addr: "no-such-host-abcxyz.invalid:7443"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return tr, nil },
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("a name that does not resolve must not stop the daemon starting: %v", err)
	}
	defer pool.Close()

	waitForDials(t, tr, 1, 5*time.Second)

	states := pool.State()
	if len(states) != 1 {
		t.Fatalf("got %d servers, want 1", len(states))
	}
	if states[0].State != "connecting" {
		t.Errorf("session is %q, want %q: a server still being retried has not given up",
			states[0].State, "connecting")
	}
}

// TestStatusSaysWhyASessionIsNotConnected covers the reporting half. A session
// that is retrying must say what went wrong, or the only honest reading of
// "connecting" is "wait and see", forever.
func TestStatusSaysWhyASessionIsNotConnected(t *testing.T) {
	hub := mem.NewHub()
	tr := &countingDeadTransport{inner: hub.Transport("nothing-here:1")}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"web": {Addr: "nothing-here:1"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return tr, nil },
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	waitForDials(t, tr, 1, 5*time.Second)

	// Bounded poll: the reason appears once an attempt has failed, and a
	// deadline that is reached is reported as a failure rather than a stall.
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		states := pool.State()
		if len(states) == 1 && states[0].LastError != "" {
			last = states[0].LastError
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if last == "" {
		t.Fatal("a session that has failed to connect reports no reason, so status still says " +
			"only that it is connecting")
	}
	if states := pool.State(); states[0].State != "connecting" {
		t.Errorf("session is %q, want %q: reporting a reason must not change the state",
			states[0].State, "connecting")
	}
}

// TestNothingIsReportedWhenNothingIsWrong keeps the field out of documents that
// have no failure to describe. A reason attached to a healthy or disabled server
// would invent a problem that does not exist, and would change the shape of
// output that scripts already read.
func TestNothingIsReportedWhenNothingIsWrong(t *testing.T) {
	hub := mem.NewHub()
	agent := hub.Transport("listener:1")
	ln, err := agent.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			_ = c
		}
	}()

	disabled := false
	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{
		"off": {Addr: "listener:1", Enabled: &disabled},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) {
			return hub.Transport("client:1"), nil
		},
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	for _, st := range pool.State() {
		if st.LastError != "" {
			t.Errorf("server %q reports %q; a server that never dialled has no failure to "+
				"describe", st.Name, st.LastError)
		}
	}

	// The rendered document must not carry the field either, so output for a
	// healthy fleet is unchanged from before the field existed.
	noSidecar := func(string) (time.Time, bool, error) { return time.Time{}, false, nil }
	snap := daemon.BuildSnapshot(pool.State(), daemon.WallClock{}, "", 0, noSidecar)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "last_error") {
		t.Errorf("status document names last_error when nothing is wrong: %s", raw)
	}
}

// TestTheSessionEnumStillHasFiveValues pins the decision that the reason is a
// field of its own rather than a sixth state. Adding a state would change a set
// of words that scripts branch on, which is a larger promise than adding a
// sentence for a person to read.
//
// It is read from the source that produces the values rather than from a list
// kept here, because a list kept here would agree with itself forever. Three
// places produce them: the two functions that turn an internal state into a
// reported one, and the entry for a server that was switched off, which reports
// its single value directly.
func TestTheSessionEnumStillHasFiveValues(t *testing.T) {
	documented := map[string]bool{
		`"connected"`:   true,
		`"connecting"`:  true,
		`"listening"`:   true,
		`"disabled"`:    true,
		`"auth_failed"`: true,
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("cannot read this package's source: %v", err)
	}

	found := map[string]bool{}
	inspected := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				name := fn.Name.Name
				isLabeller := name == "dialStateLabel" || name == "listenStateLabel"
				isDisabled := name == "State" && receiverName(fn) == "disabledEntry"
				if !isLabeller && !isDisabled {
					return true
				}
				inspected++
				ast.Inspect(fn, func(inner ast.Node) bool {
					if lit, ok := inner.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						found[lit.Value] = true
					}
					return true
				})
				return false
			})
		}
	}

	if inspected != 3 {
		t.Fatalf("found %d of the 3 places that produce a reported session value; if any was "+
			"renamed or moved, this check is no longer looking at all of them", inspected)
	}

	for lit := range found {
		if !documented[lit] {
			t.Errorf("status can report session %s, which is not one of the five documented "+
				"values; a new state changes what every script reading this must handle", lit)
		}
	}
	for lit := range documented {
		if !found[lit] {
			t.Errorf("session value %s is documented but no longer produced anywhere", lit)
		}
	}
}

// receiverName reports the type a method is defined on, without its pointer.
func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// TestTheReportedReasonCannotDisturbTheOutput covers the part of the reason that
// does not originate here. A failure can carry text chosen by the far end, and
// this field is printed beside others and parsed by scripts, so it must not be
// able to add a line, move a cursor, or run on for a screenful.
func TestTheReportedReasonCannotDisturbTheOutput(t *testing.T) {
	hostile := "boom\r\nsession=connected\x1b]0;title\x07" +
		strings.Repeat("padding ", 200) + "\xff\xfe"

	hub := mem.NewHub()
	tr := &failingTextTransport{inner: hub.Transport("nothing-here:1"), text: hostile}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"web": {Addr: "nothing-here:1"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return tr, nil },
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	deadline := time.Now().Add(5 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		if states := pool.State(); len(states) == 1 && states[0].LastError != "" {
			got = states[0].LastError
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got == "" {
		t.Fatal("no reason was reported, so the guards below assert nothing")
	}

	if len(got) > 256 {
		t.Errorf("reported reason is %d bytes; it is meant to be capped so one field cannot "+
			"fill the output", len(got))
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("reported reason contains a line break, so it can pretend to be a second "+
			"line of output: %q", got)
	}
	if strings.ContainsRune(got, '\x1b') {
		t.Errorf("reported reason contains an escape character, so it can act on the terminal "+
			"that prints it: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("reported reason is not valid text: %q", got)
	}
}

// failingTextTransport fails every dial with an error whose text the test
// chooses, standing in for a failure whose wording came from the far end.
type failingTextTransport struct {
	inner transport.Transport
	text  string
}

func (t *failingTextTransport) Dial(_ context.Context, _ string) (transport.Conn, error) {
	return nil, errors.New(t.text)
}
func (t *failingTextTransport) Listen() (transport.Listener, error) { return t.inner.Listen() }
func (t *failingTextTransport) Close() error                        { return t.inner.Close() }

// TestTheReportedReasonKeepsItsNameInTheDocument pins the spelling of the field
// in the document itself. The name is what scripts read, so renaming it is a
// change to a published shape rather than an internal tidy-up, and the version
// number beside it has to move when it happens.
func TestTheReportedReasonKeepsItsNameInTheDocument(t *testing.T) {
	states := []daemon.SessionState{{
		Name:      "web",
		State:     "connecting",
		Transport: "dial",
		LastError: "nothing is listening there",
	}}
	noSidecar := func(string) (time.Time, bool, error) { return time.Time{}, false, nil }

	raw, err := json.Marshal(daemon.BuildSnapshot(states, daemon.WallClock{}, "", 0, noSidecar))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc struct {
		Schema  int `json:"schema"`
		Servers []struct {
			LastError string `json:"last_error"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].LastError != "nothing is listening there" {
		t.Errorf("the reason is not published as last_error: %s", raw)
	}
	if doc.Schema != 2 {
		t.Errorf("document version is %d, want 2; the version has to move when the shape does",
			doc.Schema)
	}
}

// TestAnAddressInEitherFamilyIsAccepted guards the other side of the refusal:
// a server that can be reached must not be turned away before anything is
// tried. Both families are dialled, each on its own socket, so neither is a
// reason to refuse.
//
// It exists because the refusal above once included a family rule, and a rule
// like that is easy to reinstate by someone reading only the failing half.
func TestAnAddressInEitherFamilyIsAccepted(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"IPv4", "192.0.2.10:7443"},
		{"IPv6", "[2001:db8::1]:7443"},
		{"IPv6 with an interface name", "[fe80::1%lo]:7443"},
	}

	for _, tc := range cases {
		hub := mem.NewHub()
		cfg := config.Defaults()
		cfg.Servers = map[string]config.Server{"web": {Addr: tc.addr}}

		ctx, cancel := context.WithCancel(context.Background())
		pool, err := daemon.NewRealPool(
			ctx, cfg,
			func(_ string, _ config.Server) (transport.Transport, error) {
				return hub.Transport("either:1"), nil
			},
			ceilingPolicy(), daemon.WallClock{}, nil,
		)
		if err != nil {
			t.Errorf("%s: a server at %s was refused, so it could never be reached even when it "+
				"is there: %v", tc.name, tc.addr, err)
			cancel()
			continue
		}
		pool.Close()
		cancel()
	}
}

// TestTheReasonStaysVisibleWhileASessionIsDown covers the difference between
// having a reason and being asked for it at the right moment.
//
// The reason used to be cleared just before each new attempt, so it existed
// only during the pause between attempts. That is the opposite of when anyone
// asks: an attempt against an unreachable address runs until it times out,
// which is most of the wall-clock time and nearly all of it when the far end
// is silent rather than refusing. Asked during an attempt, a session that had
// never once connected reported no reason at all.
//
// The dial here takes time to fail, which is what makes the test able to fail:
// against a transport that fails instantly there is no interval to catch, and
// the same assertion would pass whether the defect was present or not.
func TestTheReasonStaysVisibleWhileASessionIsDown(t *testing.T) {
	tr := &slowFailingTransport{delay: 150 * time.Millisecond}

	cfg := config.Defaults()
	cfg.Servers = map[string]config.Server{"web": {Addr: "nothing-here:1"}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := daemon.NewRealPool(
		ctx, cfg,
		func(_ string, _ config.Server) (transport.Transport, error) { return tr, nil },
		ceilingPolicy(), daemon.WallClock{}, nil,
	)
	if err != nil {
		t.Fatalf("NewRealPool: %v", err)
	}
	defer pool.Close()

	// Wait for the first failure, so there is a reason to report at all.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := pool.State(); len(st) == 1 && st[0].LastError != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := pool.State(); st[0].LastError == "" {
		t.Fatal("no reason was reported even once, so this test cannot say anything about " +
			"whether it stays reported")
	}

	// From here the reason must never disappear. The sampling deliberately
	// spans several attempts, each of which takes long enough to be sampled
	// during rather than only between.
	var absent int
	const samples = 60
	for i := 0; i < samples; i++ {
		st := pool.State()
		if len(st) != 1 {
			t.Fatalf("got %d servers, want 1", len(st))
		}
		if st[0].State != "connecting" {
			t.Fatalf("session is %q, want connecting: this test only means something while the "+
				"session is still trying", st[0].State)
		}
		if st[0].LastError == "" {
			absent++
		}
		time.Sleep(10 * time.Millisecond)
	}

	if absent > 0 {
		t.Errorf("the reason was missing in %d of %d samples of a session that has never "+
			"connected; it is being cleared around each attempt rather than describing the "+
			"situation, so whoever asks during an attempt is told nothing", absent, samples)
	}
}

// slowFailingTransport fails every dial, but not instantly. The delay is the
// point: it stands in for an address that is silent rather than refusing, where
// each attempt runs until it times out.
type slowFailingTransport struct {
	delay time.Duration
}

func (t *slowFailingTransport) Dial(ctx context.Context, _ string) (transport.Conn, error) {
	select {
	case <-time.After(t.delay):
		return nil, errors.New("no response from server")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *slowFailingTransport) Listen() (transport.Listener, error) {
	return nil, errors.New("this transport only dials")
}
func (t *slowFailingTransport) Close() error { return nil }
