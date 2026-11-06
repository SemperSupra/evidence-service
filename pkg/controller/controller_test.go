package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/admission"
)

type testGrantStore struct{ grant admission.Grant }

func (s *testGrantStore) Lookup(_ context.Context, id string) (admission.Grant, error) {
	if id != s.grant.ID {
		return admission.Grant{}, errors.New("missing grant")
	}
	return s.grant, nil
}

type testMetadata struct {
	calls int
	summary Summary
}

func (m *testMetadata) GetSummary(_ context.Context, _ string) (Summary, error) {
	m.calls++
	return m.summary, nil
}

type testQueue struct{ calls int }

func (q *testQueue) Propose(_ context.Context, sessionID, _ string) (ReplayProposal, error) {
	q.calls++
	return ReplayProposal{ProposalID: "synthetic-proposal-1", SessionID: sessionID, Accepted: true}, nil
}

func setup() (Controller, admission.Principal, *testGrantStore, *testMetadata, *testQueue, time.Time) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	grants := &testGrantStore{grant: admission.Grant{
		ID: "approved-grant", SubjectID: "actor-a", SessionID: "owned-synthetic-session",
		IssuerID: "test-approver", Approved: true,
		Actions: map[admission.Operation]bool{
			admission.InspectMetadata: true,
			admission.RequestReplay: true,
		},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}}
	meta := &testMetadata{summary: Summary{SessionID: "owned-synthetic-session", EvidenceGrade: "CORRELATED_METADATA_ONLY", ArtifactCount: 3}}
	queue := &testQueue{}
	c := Controller{Policy: admission.Engine{Store: grants}, Metadata: meta, Queue: queue, Clock: func() time.Time { return now }}
	return c, admission.Principal{SubjectID: "actor-a", Role: admission.Agent, Authenticated: true}, grants, meta, queue, now
}

func TestAgentUsesSharedMetadataAndProposalButNeverRunsReplay(t *testing.T) {
	c, p, _, meta, queue, _ := setup()
	seen, err := c.InspectMetadata(context.Background(), p, "approved-grant", "owned-synthetic-session")
	if err != nil || seen.ArtifactCount != 3 {
		t.Fatalf("metadata denied: %+v %v", seen, err)
	}
	proposal, err := c.RequestReplay(context.Background(), p, "approved-grant", "owned-synthetic-session")
	if err != nil || !proposal.Accepted || proposal.ProposalID == "" {
		t.Fatalf("proposal denied: %+v %v", proposal, err)
	}
	if meta.calls != 1 || queue.calls != 1 {
		t.Fatal("unexpected controller effect count")
	}
}

func TestDeniedNeverInvokesEffect(t *testing.T) {
	for _, name := range []string{"revoked", "expired", "foreign-session", "foreign-subject", "unauthenticated", "wrong-grant", "no-clock", "missing-policy"} {
		t.Run(name, func(t *testing.T) {
			c, p, grants, meta, queue, now := setup()
			grantID, sessionID := "approved-grant", "owned-synthetic-session"
			switch name {
			case "revoked":
				grants.grant.Revoked = true
			case "expired":
				c.Clock = func() time.Time { return now.Add(time.Hour) }
			case "foreign-session":
				sessionID = "foreign-session"
			case "foreign-subject":
				p.SubjectID = "other"
			case "unauthenticated":
				p.Authenticated = false
			case "wrong-grant":
				grantID = "not-approved"
			case "no-clock":
				c.Clock = nil
			case "missing-policy":
				c.Policy.Store = nil
			}
			if _, err := c.InspectMetadata(context.Background(), p, grantID, sessionID); err == nil {
				t.Fatal("unauthorized metadata access")
			}
			if _, err := c.RequestReplay(context.Background(), p, grantID, sessionID); err == nil {
				t.Fatal("unauthorized proposal")
			}
			if meta.calls != 0 || queue.calls != 0 {
				t.Fatal("effect called after denial")
			}
		})
	}
}

func TestForeignMetadataCannotBeReturned(t *testing.T) {
	c, p, _, meta, _, _ := setup()
	meta.summary.SessionID = "other"
	result, err := c.InspectMetadata(context.Background(), p, "approved-grant", "owned-synthetic-session")
	if err != ErrCorrupt || result.SessionID != "" {
		t.Fatalf("foreign summary leaked: %+v %v", result, err)
	}
}

func TestOrdinaryAgentCannotRequestSecretRecovery(t *testing.T) {
	c, p, _, _, _, now := setup()
	if c.Policy.Decide(context.Background(), p, "approved-grant", "owned-synthetic-session", admission.RecoverSecrets, now).Allowed {
		t.Fatal("agent acquired raw secret authority")
	}
}
