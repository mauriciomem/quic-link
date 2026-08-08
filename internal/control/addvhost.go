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
	if r, ok := req.(*controlpb.AddVhostRequest); ok {
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
	default:
		return "the name could not be published"
	}
}

// publishStatus maps a publish failure to what the caller is told. The
// distinction is kept because the remedies differ: choose another name, fix the
// request, or nothing the caller can do.
func publishStatus(err error) error {
	switch {
	case errors.Is(err, ErrNameTaken):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrNameRejected):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, "the name could not be published")
	}
}

// auditMutation records an attempt to change what this agent publishes.
//
// Everything that changes the agent's own behaviour is written down with who
// asked, what they asked about, and what happened, because a change made
// remotely is otherwise invisible: nothing this agent reports lists the names
// it has been asked to publish, and they are gone when it restarts. Only the
// short form of the caller's identity is recorded — enough to recognise who it
// was, never the whole credential.
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
