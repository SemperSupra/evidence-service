package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/SemperSupra/evidence-service/pkg/admission"
)

type storedProposal struct {
	intent   ProposalIntent
	proposal ReplayProposal
}

type onceTestQueue struct {
	mu      sync.Mutex
	records map[string]storedProposal
	commits int
	legacy  int
}

func (q *onceTestQueue) Propose(context.Context, string, string) (ReplayProposal, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.legacy++
	return ReplayProposal{}, errors.New("non-idempotent proposal path unavailable")
}

func (q *onceTestQueue) ProposeOnce(ctx context.Context, intent ProposalIntent) (ReplayProposal, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ReplayProposal{}, err
	}
	if q.records == nil {
		q.records = make(map[string]storedProposal)
	}
	if old, ok := q.records[intent.IdempotencyKey]; ok {
		if old.intent != intent {
			return ReplayProposal{}, errors.New("cross-scope key reuse")
		}
		return old.proposal, nil
	}
	q.commits++
	proposal := ReplayProposal{
		ProposalID: fmt.Sprintf("test-proposal-%d", q.commits),
		SessionID:  intent.SessionID,
		Accepted:   true,
	}
	q.records[intent.IdempotencyKey] = storedProposal{intent: intent, proposal: proposal}
	return proposal, nil
}

func TestReplayOnceConcurrentRetriesProduceOneProposal(t *testing.T) {
	c, p, _, _, _, _ := setup()
	queue := &onceTestQueue{}
	c.Queue = queue
	const attempts = 40
	type result struct {
		proposal ReplayProposal
		err      error
	}
	results := make(chan result, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			proposal, err := c.RequestReplayOnce(context.Background(), p, "approved-grant", "owned-synthetic-session", "shared-retry-key-001")
			results <- result{proposal: proposal, err: err}
		}()
	}
	var expected string
	for i := 0; i < attempts; i++ {
		got := <-results
		if got.err != nil || got.proposal.ProposalID == "" {
			t.Fatalf("duplicate request failed: %+v", got)
		}
		if expected == "" {
			expected = got.proposal.ProposalID
		}
		if got.proposal.ProposalID != expected {
			t.Fatal("retry created a different replay proposal")
		}
	}
	if queue.commits != 1 || queue.legacy != 0 {
		t.Fatalf("proposal deduplication failed: %+v", queue)
	}
}

func TestReplayOnceRejectsRevokedAndUnscopedRequests(t *testing.T) {
	c, p, grants, _, _, _ := setup()
	queue := &onceTestQueue{}
	c.Queue = queue
	ctx := context.Background()
	for _, key := range []string{"", "short", "wrong/unsafe/key"} {
		if _, err := c.RequestReplayOnce(ctx, p, "approved-grant", "owned-synthetic-session", key); err == nil {
			t.Fatalf("accepted invalid idempotency key %q", key)
		}
	}
	grants.grant.Revoked = true
	if _, err := c.RequestReplayOnce(ctx, p, "approved-grant", "owned-synthetic-session", "valid-test-key-001"); err == nil {
		t.Fatal("revoked proposal reached queue")
	}
	grants.grant.Revoked = false
	p.Authenticated = false
	if _, err := c.RequestReplayOnce(ctx, p, "approved-grant", "owned-synthetic-session", "valid-test-key-001"); err == nil {
		t.Fatal("unverified principal reached queue")
	}
	if queue.commits != 0 || queue.legacy != 0 {
		t.Fatal("unauthorized proposal had side effects")
	}
}

func TestReplayOnceCrossSessionKeyCollisionFailsClosed(t *testing.T) {
	c, p, grants, _, _, _ := setup()
	queue := &onceTestQueue{}
	c.Queue = queue
	ctx := context.Background()
	key := "shared-across-session-001"
	first, err := c.RequestReplayOnce(ctx, p, "approved-grant", "owned-synthetic-session", key)
	if err != nil || first.ProposalID == "" {
		t.Fatalf("first proposal rejected: %v", err)
	}
	grants.grant.SessionID = "different-owned-session"
	if _, err := c.RequestReplayOnce(ctx, p, "approved-grant", "different-owned-session", key); err == nil {
		t.Fatal("idempotency key silently rebound to another authorized session")
	}
	if queue.commits != 1 {
		t.Fatal("collision created an extra proposal")
	}
}

func TestReplayOnceRequiresTransactionalBackend(t *testing.T) {
	c, p, _, _, _, _ := setup()
	if _, err := c.RequestReplayOnce(context.Background(), p, "approved-grant", "owned-synthetic-session", "valid-test-key-001"); err != ErrUnavailable {
		t.Fatalf("legacy-only queue incorrectly accepted: %v", err)
	}
	c.Queue = &onceTestQueue{}
	p.Role = admission.Agent
	if _, err := c.RequestReplayOnce(context.Background(), p, "approved-grant", "owned-synthetic-session", "valid-test-key-001"); err != nil {
		t.Fatalf("scoped agent proposal was rejected: %v", err)
	}
}
