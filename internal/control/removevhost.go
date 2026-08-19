package control

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	controlpb "github.com/mauriciomem/quic-link/internal/control/proto"
)

// RemoveVhost withdraws a name that was published over this connection.
//
// It reports the method as unimplemented when this agent has no way to withdraw
// anything, for the same reason publishing does: the ability is withheld unless
// the operator asked for it, and an agent built before the method existed answers
// identically. From a caller's position those are one fact.
//
// Being refused for want of the operator's consent happens earlier, at the
// authorization check-point, and is recorded there. By the time this runs, either
// the operator allowed changes or the capability was withheld and there is
// nothing here to reach.
func (s server) RemoveVhost(_ context.Context, req *controlpb.RemoveVhostRequest) (*controlpb.RemoveVhostResponse, error) {
	if s.withdraw == nil {
		return nil, status.Error(codes.Unimplemented,
			"this agent cannot withdraw a published name")
	}

	host := req.GetHost()
	shadowedBy, err := s.withdraw.RemoveVhost(host)
	if err != nil {
		s.auditMutation("RemoveVhost", auditName(host), verdictRefused, withdrawReason(err))
		return nil, withdrawStatus(err)
	}

	s.auditMutation("RemoveVhost", auditName(host), verdictAllowed, "")
	return &controlpb.RemoveVhostResponse{Host: host, ShadowedBy: shadowedBy}, nil
}

// withdrawReason names why a withdrawal was refused, from a fixed vocabulary, so
// an operator reading the record can tell the cases apart without the message
// carrying anything a caller chose.
func withdrawReason(err error) string {
	switch {
	case errors.Is(err, ErrNameAbsent):
		return "the name is not published"
	case errors.Is(err, ErrNameNotOurs):
		return "the name was not published over this connection"
	case errors.Is(err, ErrNameRejected):
		return "the name was refused"
	default:
		return "the name could not be withdrawn"
	}
}

// withdrawStatus maps a withdrawal failure to what the caller is told.
//
// A name that belongs to the agent's configuration is reported as a failed
// precondition rather than a denied permission. The distinction matters to
// whoever reads it: a permission error invites asking the operator to allow
// something, and no setting makes their own configuration remotely removable.
func withdrawStatus(err error) error {
	switch {
	case errors.Is(err, ErrNameAbsent):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrNameNotOurs):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrNameRejected):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, "the name could not be withdrawn")
	}
}
