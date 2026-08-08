package tunnel_test

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

	"github.com/mauriciomem/quic-link/internal/control"
	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
	"github.com/mauriciomem/quic-link/internal/router"
	"github.com/mauriciomem/quic-link/internal/tunnel"
)

// recordSink captures whole log records rather than rendered text.
//
// The audit trail is checked field by field, so the fields have to survive
// being captured. A text buffer would flatten them into one string and a test
// asserting on that would pass for a line that merely contained the right word
// somewhere, which is the shape of assertion that lets a wrong field through.
//
// Records arrive on a buffered channel because they are written on a goroutine
// the gRPC server owns, not the test's. A channel gives the ordering guarantee
// the race detector can actually see; a shared variable does not, however
// obviously correct it looks.
type recordSink struct {
	records chan slog.Record
}

func newRecordSink() *recordSink {
	return &recordSink{records: make(chan slog.Record, 64)}
}

func (s *recordSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *recordSink) Handle(_ context.Context, r slog.Record) error {
	select {
	case s.records <- r.Clone():
	default: // never block the code under test on a full buffer
	}
	return nil
}

func (s *recordSink) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s *recordSink) WithGroup(string) slog.Handler      { return s }

// await returns the first record carrying msg, or fails.
func (s *recordSink) await(t *testing.T, msg string) slog.Record {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-s.records:
			if r.Message == msg {
				return r
			}
		case <-deadline:
			t.Fatalf("no log record with message %q arrived", msg)
		}
	}
}

func attrsOf(r slog.Record) map[string]string {
	out := make(map[string]string, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.String()
		return true
	})
	return out
}

// installRecordSink captures log records for the duration of the test. It
// replaces the process-wide default logger, so a test using it must not run in
// parallel with anything else in this package — which is why none of the
// existing log-capturing tests here are parallel either.
func installRecordSink(t *testing.T) *recordSink {
	t.Helper()
	sink := newRecordSink()
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return sink
}

// addVhostRig starts a real agent over a real QUIC session and returns a
// control client, plus the client's own pin so a test can prove the pin is
// never written to a log in full.
func addVhostRig(t *testing.T, ctx context.Context, opts tunnel.ServeOpts) (*control.Client, string) {
	t.Helper()
	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustRouter(t, map[string]string{"ssh": "tcp://127.0.0.1:22"}, nil)
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, opts)

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, clientPin
}

func addVhost(t *testing.T, ctx context.Context, c *control.Client, host string, port uint32) (*controlpb.AddVhostResponse, error) {
	t.Helper()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.AddVhost(callCtx, &controlpb.AddVhostRequest{Host: host, Port: port})
}

// TestAddVhostE2E_DefaultIsRefusedAndRecorded is the headline safety property:
// an agent whose operator said nothing about remote changes does not accept
// them, and the attempt is written down. Both halves matter — a refusal nobody
// can find afterwards is not much better than no refusal.
func TestAddVhostE2E_DefaultIsRefusedAndRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sink := installRecordSink(t)
	// Deliberately the zero value: this is the agent of an operator who never
	// considered the question.
	client, clientPin := addVhostRig(t, ctx, tunnel.ServeOpts{})

	_, err := addVhost(t, ctx, client, "grafana.server1.internal", 3000)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("publishing against a default agent returned %v, want PermissionDenied", got)
	}

	r := sink.await(t, "route mutation denied")
	if r.Level != slog.LevelWarn {
		t.Errorf("a refused change was logged at %v, want WARN", r.Level)
	}
	a := attrsOf(r)
	for k, want := range map[string]string{
		"role":    "agent",
		"method":  "AddVhost",
		"name":    "grafana.server1.internal",
		"verdict": "denied",
	} {
		if a[k] != want {
			t.Errorf("audit attr %q = %q, want %q", k, a[k], want)
		}
	}
	if a["reason"] == "" {
		t.Error("the audit line does not say why the change was refused")
	}
	if a["peer"] != clientPin[:8] {
		t.Errorf("audit attr peer = %q, want the caller's short identity %q", a["peer"], clientPin[:8])
	}
	for k, v := range a {
		if strings.Contains(v, clientPin) {
			t.Errorf("audit attr %q carries the caller's whole credential: %q", k, v)
		}
	}
}

// TestAddVhostE2E_OptedInPublishesAndRecords proves the setting actually turns
// the capability on, so the refusal above is a decision rather than a feature
// that never worked.
func TestAddVhostE2E_OptedInPublishesAndRecords(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sink := installRecordSink(t)
	client, clientPin := addVhostRig(t, ctx, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	resp, err := addVhost(t, ctx, client, "grafana.server1.internal", 3000)
	if err != nil {
		t.Fatalf("publishing against an opted-in agent: %v", err)
	}
	if resp.GetHost() != "grafana.server1.internal" || resp.GetPort() != 3000 {
		t.Errorf("the reply describes %q:%d, want the name and port that were published",
			resp.GetHost(), resp.GetPort())
	}

	r := sink.await(t, "route mutation applied")
	if r.Level != slog.LevelInfo {
		t.Errorf("an applied change was logged at %v, want INFO", r.Level)
	}
	a := attrsOf(r)
	if a["verdict"] != "allowed" || a["method"] != "AddVhost" || a["name"] != "grafana.server1.internal" {
		t.Errorf("audit line does not describe what happened: %v", a)
	}
	if a["peer"] != clientPin[:8] {
		t.Errorf("audit attr peer = %q, want %q", a["peer"], clientPin[:8])
	}
	for k, v := range a {
		if strings.Contains(v, clientPin) {
			t.Errorf("audit attr %q carries the caller's whole credential: %q", k, v)
		}
	}
}

// TestAddVhostE2E_ReadsSurviveTheDefaultPolicy guards the behaviour that
// shipped before this: an agent that refuses changes must still answer
// questions. A policy written the safe way round could easily refuse too much,
// and this is the test that would notice.
func TestAddVhostE2E_ReadsSurviveTheDefaultPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{})

	callCtx, cancelCall := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCall()
	if _, err := client.GetStatus(callCtx, &controlpb.GetStatusRequest{}); err != nil {
		t.Errorf("an agent that refuses changes also refused a status query: %v", err)
	}
	if _, err := client.Ping(callCtx, &controlpb.PingRequest{Nonce: 1}); err != nil {
		t.Errorf("an agent that refuses changes also refused a ping: %v", err)
	}
}

// TestAddVhostE2E_APermissivePolicyStillCannotPublish covers the second gate on
// its own. Even told to permit everything, an agent whose operator did not ask
// for remote changes has nothing to change with.
func TestAddVhostE2E_APermissivePolicyStillCannotPublish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{ControlPolicy: control.AllowAll{}})

	_, err := addVhost(t, ctx, client, "grafana.server1.internal", 3000)
	if got := status.Code(err); got != codes.Unimplemented {
		t.Fatalf("with a permissive policy but no operator consent, publishing returned %v, "+
			"want Unimplemented — the capability should not have been built at all", got)
	}
}

// TestAddVhostE2E_ADenyingPolicyStillRefuses covers the first gate on its own:
// the capability exists and the check-point is what stops the call.
func TestAddVhostE2E_ADenyingPolicyStillRefuses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	deny := control.PolicyFunc(func(_ control.PeerIdentity, method string) error {
		if method == "AddVhost" {
			return errors.New("refused by this test")
		}
		return nil
	})
	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{
		AllowRemoteRouteMutation: true,
		ControlPolicy:            deny,
	})

	_, err := addVhost(t, ctx, client, "grafana.server1.internal", 3000)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("with the capability present and the check-point refusing, publishing returned %v, want PermissionDenied", got)
	}
}

// TestAddVhostE2E_HostilePortsAreRefusedAtTheirOwnWidth walks the values a
// caller can send that are not ports. The large ones matter because the field
// is wider than a port: narrowing before checking would make the refusal quote
// a number nobody sent.
func TestAddVhostE2E_HostilePortsAreRefusedAtTheirOwnWidth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	for _, port := range []uint32{0, 65536, 1 << 31, 1<<32 - 1, 4294901761} {
		_, err := addVhost(t, ctx, client, "grafana.server1.internal", port)
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("port %d returned %v, want InvalidArgument", port, got)
		}
		if err == nil {
			continue
		}
		if !strings.Contains(err.Error(), "1-65535") {
			t.Errorf("the refusal for port %d does not say what a usable port is: %v", port, err)
		}
		// The refusal must quote the number that was actually sent. A value
		// this large does not fit the width a port is stored in, and reporting
		// it after it had been narrowed would describe a different request
		// than the one that arrived — sending whoever reads the message, or
		// the log line beside it, looking for a request nobody made.
		if !strings.Contains(err.Error(), fmt.Sprintf("port %d ", port)) {
			t.Errorf("the refusal for port %d does not name that port: %v", port, err)
		}
	}
}

// TestAddVhostE2E_ARefusedNameCannotFloodTheLog is about what a caller can make
// this agent write down. The name is recorded before anything has validated it,
// and it is the caller's to choose, so it has to be bounded and stripped of
// anything that could make a rendered line say something other than what it
// records.
func TestAddVhostE2E_ARefusedNameCannotFloodTheLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sink := installRecordSink(t)
	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	// The separators are here because they are neither control nor format
	// characters: a check written against those two categories alone misses
	// them, and a reader that treats one as a line break sees output that looks
	// like more lines than were written.
	// Long enough to prove the bound, but short enough that the hostile
	// characters land inside it rather than past the cut — otherwise the checks
	// below would pass because the bytes never reached the part being tested,
	// which says nothing about whether they would have been removed.
	hostile := strings.Repeat("a", 100) + "\n\x1b]0;pwned\x07\u202e\u2028\u2029.internal"
	if _, err := addVhost(t, ctx, client, hostile, 3000); err == nil {
		t.Fatal("a 4000-byte name with control bytes in it was published")
	}

	r := sink.await(t, "route mutation refused")
	a := attrsOf(r)
	if len(a["name"]) > 128 {
		t.Errorf("the audit line recorded %d bytes of a caller-chosen name; it must be bounded", len(a["name"]))
	}
	// The characters had to survive as far as the sanitiser for their absence to
	// mean anything, so check they were not simply cut off by the bound.
	if len(a["name"]) >= 128 {
		t.Errorf("the recorded name reached the bound, so the checks below cannot tell removal "+
			"from truncation: %q", a["name"])
	}
	for _, bad := range []string{"\n", "\x1b", "\x07", "\u202e", "\u2028", "\u2029"} {
		if strings.Contains(a["name"], bad) {
			t.Errorf("the audit line kept %q from a caller-chosen name", bad)
		}
	}
	// The reason is this program's own words, never the caller's text echoed
	// back, or the bound above would be pointless.
	if strings.Contains(a["reason"], "aaaa") {
		t.Errorf("the audit line echoed the caller's own name into the reason: %q", a["reason"])
	}
}

// TestAddVhostE2E_ConfiguredNameIsNotTakenOver is the safety rule an operator
// depends on: a name they configured cannot be reassigned by a caller, and the
// refusal says which kind of entry is in the way so they can tell a collision
// from a takeover attempt.
func TestAddVhostE2E_ConfiguredNameIsNotTakenOver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	serverKey, serverPin := mustGenIdentity(t)
	clientKey, clientPin := mustGenIdentity(t)
	serverTLS := mustServerTLS(t, serverKey, []string{clientPin})
	clientTLS := mustClientTLS(t, clientKey, serverPin)

	rtr := mustVhostRouterFor(t, map[string]string{"grafana.server1.internal": "tcp://127.0.0.1:3000"})
	serverAddr := mustStartServe(t, ctx, serverTLS, rtr, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	conn := dialConn(t, ctx, clientTLS, serverAddr)
	client, err := control.Open(ctx, conn, "test-client", control.OpenOpts{})
	if err != nil {
		t.Fatalf("control.Open: %v", err)
	}
	defer client.Close()

	_, err = addVhost(t, ctx, client, "grafana.server1.internal", 9999)
	if got := status.Code(err); got != codes.AlreadyExists {
		t.Fatalf("publishing over a configured name returned %v, want AlreadyExists", got)
	}
	if !strings.Contains(err.Error(), "configuration") {
		t.Errorf("the refusal does not say the name came from configuration: %v", err)
	}
}

// TestAddVhostE2E_RepeatingAnIdenticalRequestSucceeds looks surprising next to
// the test above and is deliberate: there is no way to withdraw a published
// name yet, so a repeat that failed would leave an agent restart as the only
// way forward. It is allowed only because the outcome asked for already holds.
func TestAddVhostE2E_RepeatingAnIdenticalRequestSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	if _, err := addVhost(t, ctx, client, "grafana.server1.internal", 3000); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if _, err := addVhost(t, ctx, client, "grafana.server1.internal", 3000); err != nil {
		t.Errorf("repeating the identical request was refused: %v", err)
	}
	if _, err := addVhost(t, ctx, client, "grafana.server1.internal", 4000); status.Code(err) != codes.AlreadyExists {
		t.Errorf("republishing the same name elsewhere returned %v, want AlreadyExists", status.Code(err))
	}
}

// TestAddVhostE2E_WildcardsAreRefused pins the rule at the boundary a caller
// actually reaches, so it cannot regress from this side even though the check
// itself lives further in.
func TestAddVhostE2E_WildcardsAreRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, _ := addVhostRig(t, ctx, tunnel.ServeOpts{AllowRemoteRouteMutation: true})

	for _, host := range []string{
		"*.server1.internal", "*", "*x.server1.internal",
		"a.*.internal", "fo*o.internal", "grafana.*", "x*",
	} {
		_, err := addVhost(t, ctx, client, host, 3000)
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("publishing %q returned %v, want InvalidArgument", host, got)
		}
	}
}

// mustVhostRouterFor builds a route table that already publishes some names, so
// a test can check what happens when a caller asks for one of them.
func mustVhostRouterFor(t *testing.T, hosts map[string]string) *router.Router {
	t.Helper()
	r, err := router.NewWithVhosts(nil, hosts, nil)
	if err != nil {
		t.Fatalf("router.NewWithVhosts: %v", err)
	}
	return r
}
