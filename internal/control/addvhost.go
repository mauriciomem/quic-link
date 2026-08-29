package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// Errors a VhostPublisher may report. They are declared here, rather than
// reused from whichever package owns the name table, because this package must
// not depend on that one: a control-plane RPC and the thing it administers are
// deliberately separable. Whatever supplies the publisher translates its own
// errors into these at the boundary that already knows both.
var (
	// ErrNameTaken reports that the name is already published and was left
	// alone. The remedy is to choose another name.
	ErrNameTaken = errors.New("control: that name is already published")
	// ErrNameRejected reports that the request itself was not acceptable. The
	// remedy is to fix what was asked for.
	ErrNameRejected = errors.New("control: the name or port was refused")
	// ErrNameAbsent reports that a name asked to be withdrawn is not published.
	// The remedy is nothing: the state the caller wanted already holds.
	ErrNameAbsent = errors.New("control: that name is not published")
	// ErrNameNotOurs reports that a name exists but was not published over the
	// control plane, so a caller there may not take it away. Kept separate from
	// a permission failure because no setting an operator could change makes
	// their own configuration remotely removable — telling a caller to ask for
	// permission would send them somewhere that cannot help.
	ErrNameNotOurs = errors.New("control: that name was not published over this connection")
	// ErrNameLimit reports that the agent already holds as many published names
	// as it will. The remedy is not another name: something has to be withdrawn
	// first, or the agent restarted by whoever runs it.
	ErrNameLimit = errors.New("control: this agent holds as many published names as it will")
)

// VhostPublisher publishes one hostname on this agent while it runs.
//
// The target is a port, not an address. A caller that could name an arbitrary
// destination could point the agent at a privileged local socket or at another
// machine on its network, and then the thing that decides where traffic may go
// would be taking instructions instead. A parameter that cannot express a
// destination has no edge case a validator could miss.
type VhostPublisher interface {
	AddVhost(host string, port int) error
}

// VhostWithdrawer takes back a name that was published over this connection.
//
// It is a separate interface from the publisher so that a caller supplying one
// is not forced to supply the other, and so a test can provide either alone. The
// two are withheld together in practice, because an agent that may not be added
// to has nothing a caller could take away.
//
// The first returned string names a pattern that resumes serving the name once
// the exact entry is gone, and the second is the address that pattern points
// at. Both are empty when nothing takes over. Reporting them is what keeps a
// successful withdrawal from implying more than happened — and reporting the
// address alongside the pattern is what keeps it from raising a question it
// then refuses to answer, since where the name is served now is what a caller
// asks next.
//
// The address is supplied here rather than fetched by a follow-up listing
// because whatever implements this holds the covering entry at the moment of
// the deletion, so what it returns describes the table as it then is. A second
// call is a second round trip that could reach a different process.
type VhostWithdrawer interface {
	RemoveVhost(host string) (shadowedBy, shadowedByAddress string, err error)
}

// changesTheAgent reports whether a method changes what this agent does, as
// opposed to reporting on it.
//
// There is deliberately only one list, and it names the calls that are safe
// without permission — so anything else is treated as a change. Two lists, one
// naming what to refuse and one naming what to write down, would eventually
// disagree, and the way that disagreement shows up is the worst of both: a
// change refused with no record of anyone having tried.
//
// It also decides the answer for a method nobody has classified yet, and
// decides it the safe way: a call this build does not recognize is treated as
// a change, so it is refused and recorded rather than waved through.
func changesTheAgent(method string) bool {
	return !readOnlyMethods[method]
}

// maxAuditedNameLen bounds how much of a caller's requested name is written to
// the log.
//
// A refused name reaches the log before anything has validated it, and the
// caller chooses it: without a bound, one rejected call writes as much text
// into the agent's log as the caller cares to send. A hostname cannot exceed
// 253 bytes and a plausible one is far shorter, so anything past this is not
// information an operator was going to use.
const maxAuditedNameLen = 128

// auditName makes a caller-supplied name safe to write to a log.
//
// Log output is read by people, through terminals and log viewers, and a name
// arrives here having been chosen by whoever is calling — including a caller
// whose key is correct but whose intentions are not. Characters that reposition
// or reformat text can make a rendered line say something other than what it
// records, so they are removed rather than escaped: escaping depends on the
// output format, and the format is the operator's choice, not this code's.
//
// internal/ipc.SanitizeAgentString is this function's general-purpose
// sibling, solving the identical problem for far-end text crossing the IPC
// relay boundary rather than a name written to this agent's own log. The two
// cannot share an implementation — internal/ipc already depends on
// internal/control, so importing the other way would cycle — and agree on
// all five rune classes removed, but differ deliberately: bound (128 here,
// 256 there), U+FFFD handling (dropped here even when legitimately typed,
// since a hostname has no legitimate use for it; kept there when it decoded
// cleanly), and this function emits no truncation marker, while that one
// does. A change to the rune-class rule on one side is worth checking
// against the other.
func auditName(s string) string {
	if len(s) > maxAuditedNameLen {
		s = s[:maxAuditedNameLen]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// Also drops a legitimately-typed replacement character, which is
			// deliberate: it is not worth distinguishing one from a byte that
			// failed to decode when neither belongs in a hostname.
			continue
		case unicode.IsControl(r):
			continue
		case unicode.Is(unicode.Cf, r):
			// Format characters, which includes the ones that flip the
			// direction text is read in.
			continue
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			// Line and paragraph separators. They are neither control nor
			// format characters, so the two cases above miss them, and a
			// reader that treats them as line breaks would see a log line
			// that appears to be two.
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// auditedName extracts the name a request is about, for the audit trail. It is
// used where the request is not yet a known type — the authorization
// check-point sees every call before dispatch — so an unrecognised shape
// reports nothing rather than guessing. A missing name in a log line is a
// question; a wrong one is a wrong answer.
func auditedName(req any) string {
	switch r := req.(type) {
	case *controlpb.AddVhostRequest:
		return auditName(r.GetHost())
	case *controlpb.RemoveVhostRequest:
		return auditName(r.GetHost())
	}
	return ""
}

// AddVhost publishes a hostname pointing at a port on the agent's own loopback
// interface, for as long as this process runs.
//
// It reports the method as unimplemented when this agent has no way to publish
// anything. That is a real state, not a defect: the ability is withheld unless
// the operator asked for it, and an agent built before the method existed
// answers identically. From a caller's position those are one fact — this agent
// cannot do that — so they are deliberately not distinguished. Being refused
// permission is a different fact with a different remedy, and is reported
// separately by the check-point before this is ever reached.
func (s server) AddVhost(_ context.Context, req *controlpb.AddVhostRequest) (*controlpb.AddVhostResponse, error) {
	const method = "AddVhost"
	name := auditedName(req)

	if s.names == nil {
		return nil, status.Error(codes.Unimplemented,
			"this agent has no way to change what it publishes")
	}

	host := req.GetHost()
	port := req.GetPort()
	// Checked at the width it arrived in, before being narrowed. A value this
	// large cannot be a port either way, but narrowing first would make the
	// refusal quote a different number than the caller sent, and whoever read
	// that line afterwards would be looking for the wrong request.
	if port < 1 || port > 65535 {
		reason := fmt.Sprintf("port %d is outside the usable range 1-65535", port)
		s.auditMutation(method, name, verdictRefused, reason)
		return nil, status.Error(codes.InvalidArgument, reason)
	}

	if err := s.names.AddVhost(host, int(port)); err != nil {
		s.auditMutation(method, name, verdictRefused, publishReason(err))
		return nil, publishStatus(err)
	}

	s.auditMutation(method, name, verdictAllowed, "")
	return &controlpb.AddVhostResponse{Host: host, Port: port}, nil
}

// The three outcomes an attempt to change something can have. A caller that was
// not permitted to ask and one that asked for something impossible are both
// refusals, but they are not the same refusal: one is fixed by changing a
// permission and the other by changing the request, and an operator sent to the
// wrong one loses time.
const (
	verdictAllowed = "allowed"
	verdictDenied  = "denied"
	verdictRefused = "refused"
)

// publishReason names why a publish attempt failed, in a fixed vocabulary.
//
// The underlying error quotes the name it was given, and that name came from
// the caller, so passing it through would let a caller write as much of its own
// text into the log as it likes. The name is already recorded, bounded, in its
// own field.
func publishReason(err error) string {
	switch {
	case errors.Is(err, ErrNameTaken):
		return "the name is already published"
	case errors.Is(err, ErrNameRejected):
		return "the name or port was refused"
	case errors.Is(err, ErrNameLimit):
		return "the agent holds as many names as it will"
	default:
		return "the name could not be published"
	}
}

// publishStatus maps a publish failure to what the caller is told. The
// distinction is kept because the remedies differ: choose another name, fix the
// request, take a name back or ask the agent's operator to restart it, or
// nothing the caller can do.
func publishStatus(err error) error {
	switch {
	case errors.Is(err, ErrNameTaken):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrNameRejected):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrNameLimit):
		return status.Error(codes.ResourceExhausted, err.Error())
	default:
		return status.Error(codes.Internal, "the name could not be published")
	}
}

// auditMutation records an attempt to change what this agent publishes.
//
// Everything that changes the agent's own behaviour is written down with who
// asked, what they asked about, and what happened. The names themselves can now
// be listed, but that says only what is published — not who asked for it, when,
// or what was refused. A refusal in particular exists nowhere else: it changed
// nothing, so there is no state left over to notice it by, and it is the record
// an operator most needs. Only the short form of the caller's identity is
// recorded — enough to recognise who it was, never the whole credential.
func (s server) auditMutation(method, name, verdict, reason string) {
	attrs := []any{
		"role", "agent",
		"peer", s.peer.Short(),
		"method", method,
		"name", name,
		"verdict", verdict,
	}
	if verdict == verdictAllowed {
		slog.Info("route mutation applied", attrs...)
		return
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	slog.Warn("route mutation "+verdict, attrs...)
}
