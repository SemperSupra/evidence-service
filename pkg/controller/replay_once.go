package controller

import (
	"context"
	"regexp"

	"github.com/SemperSupra/evidence-service/pkg/admission"
)

// ProposalIntent is a non-privileged, scoped, idempotent queue request. The
// identity and grant fields MUST be filled by trusted middleware, never copied
// from an agent's claimed identity or an unverified JSON role.
type ProposalIntent struct {
	SessionID      string
	SubjectID      string
	GrantID        string
	IdempotencyKey string
}

// OnceQueue must atomically persist and deduplicate requests by key. Reusing
// a key for a different actor/session/grant must fail closed. Duplicate
// requests with identical scope must return the same durable proposal ID.
// Implementations MUST NOT execute replay, export evidence or unwrap keys.
type OnceQueue interface {
	ProposeOnce(context.Context, ProposalIntent) (ReplayProposal, error)
}

var validIdempotencyKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

// RequestReplayOnce enforces common admission and then submits an intent to
// an atomic, persistence-capable queue. It does not itself create a durable
// queue: until a trusted OnceQueue is configured, admission fails closed.
func (c Controller) RequestReplayOnce(ctx context.Context, p admission.Principal, grantID, sessionID, idempotencyKey string) (ReplayProposal, error) {
	if err := ctx.Err(); err != nil {
		return ReplayProposal{}, err
	}
	if err := c.authorize(ctx, p, grantID, sessionID, admission.RequestReplay); err != nil {
		return ReplayProposal{}, err
	}
	if !validIdempotencyKey.MatchString(idempotencyKey) {
		return ReplayProposal{}, ErrDenied
	}
	if c.Queue == nil {
		return ReplayProposal{}, ErrUnavailable
	}
	queue, ok := c.Queue.(OnceQueue)
	if !ok {
		return ReplayProposal{}, ErrUnavailable
	}
	proposal, err := queue.ProposeOnce(ctx, ProposalIntent{
		SessionID: sessionID, SubjectID: p.SubjectID,
		GrantID: grantID, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return ReplayProposal{}, ErrUnavailable
	}
	if !proposal.Accepted || proposal.ProposalID == "" || proposal.SessionID != sessionID {
		return ReplayProposal{}, ErrCorrupt
	}
	return proposal, nil
}
