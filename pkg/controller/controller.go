// Package controller is a non-privileged shared evidence control primitive.
// It is deliberately transport-neutral: human/AT UI, CLI and MCP adapters
// must all use its admission boundary rather than implementing separate policy.
package controller

import (
	"context"
	"errors"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/admission"
)

// Summary contains approved metadata only; never raw captured traffic,
// decrypted content, TLS keys, tokens, headers, or user prompts.
type Summary struct {
	SessionID     string `json:"session_id"`
	EvidenceGrade string `json:"evidence_grade"`
	CaptureGap    bool   `json:"capture_gap"`
	ArtifactCount int    `json:"artifact_count"`
}

type MetadataStore interface {
	GetSummary(context.Context, string) (Summary, error)
}

// ReplayProposal is not a replay authorization or execution command.
type ReplayProposal struct {
	ProposalID string `json:"proposal_id"`
	SessionID  string `json:"session_id"`
	Accepted   bool   `json:"accepted"`
}

// ProposalQueue must persist a request for later independent custodian
// authorization. It must not initiate packet decryption or key recovery.
type ProposalQueue interface {
	Propose(context.Context, string, string) (ReplayProposal, error)
}

type Controller struct {
	Policy   admission.Engine
	Metadata MetadataStore
	Queue    ProposalQueue
	Clock    func() time.Time
}

var ErrDenied = errors.New("evidence operation denied")
var ErrUnavailable = errors.New("evidence control dependency unavailable")
var ErrCorrupt = errors.New("evidence metadata scope mismatch")

func (c Controller) authorize(ctx context.Context, p admission.Principal, grantID, sessionID string, action admission.Operation) error {
	if c.Clock == nil {
		return ErrUnavailable
	}
	if !c.Policy.Decide(ctx, p, grantID, sessionID, action, c.Clock()).Allowed {
		return ErrDenied
	}
	return nil
}

// InspectMetadata never returns a vault artifact or packet bytes. The
// identity and trusted grant must be supplied by an independent authentication
// and authorization store; caller-supplied role claims are not acceptable.
func (c Controller) InspectMetadata(ctx context.Context, p admission.Principal, grantID, sessionID string) (Summary, error) {
	if err := c.authorize(ctx, p, grantID, sessionID, admission.InspectMetadata); err != nil {
		return Summary{}, err
	}
	if c.Metadata == nil {
		return Summary{}, ErrUnavailable
	}
	result, err := c.Metadata.GetSummary(ctx, sessionID)
	if err != nil {
		return Summary{}, ErrUnavailable
	}
	if result.SessionID != sessionID || result.ArtifactCount < 0 {
		return Summary{}, ErrCorrupt
	}
	return result, nil
}

// RequestReplay only enqueues a proposal; it never executes replay or
// retrieves a key. A later trusted worker must reauthorize actual effects.
func (c Controller) RequestReplay(ctx context.Context, p admission.Principal, grantID, sessionID string) (ReplayProposal, error) {
	if err := c.authorize(ctx, p, grantID, sessionID, admission.RequestReplay); err != nil {
		return ReplayProposal{}, err
	}
	if c.Queue == nil {
		return ReplayProposal{}, ErrUnavailable
	}
	proposal, err := c.Queue.Propose(ctx, sessionID, p.SubjectID)
	if err != nil {
		return ReplayProposal{}, ErrUnavailable
	}
	if proposal.SessionID != sessionID || proposal.ProposalID == "" || !proposal.Accepted {
		return ReplayProposal{}, ErrCorrupt
	}
	return proposal, nil
}
