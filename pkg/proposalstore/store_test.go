package proposalstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/admission"
	"github.com/SemperSupra/evidence-service/pkg/controller"
)

func fixture(t *testing.T) (*Store, string, controller.ProposalIntent) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-proposals")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	intent := controller.ProposalIntent{
		SessionID: "synthetic-session-1",
		SubjectID: "actor-a",
		GrantID: "grant-1",
		IdempotencyKey: "owned-test-retry-key-0001",
	}
	return store, root, intent
}

func TestConcurrentReopenAndScopeCollision(t *testing.T) {
	a, directory, intent := fixture(t)
	b, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 50
	results := make(chan controller.ReplayProposal, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := a
			if n%2 == 0 {
				s = b
			}
			p, e := s.ProposeOnce(context.Background(), intent)
			results <- p
			errs <- e
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent retry denied: %v", err)
		}
	}
	var id string
	for p := range results {
		if p.ProposalID == "" || !p.Accepted || p.SessionID != intent.SessionID {
			t.Fatalf("bad proposal: %+v", p)
		}
		if id == "" {
			id = p.ProposalID
		}
		if p.ProposalID != id {
			t.Fatal("one key committed multiple proposal IDs")
		}
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reopened.ProposeOnce(context.Background(), intent)
	if err != nil || p.ProposalID != id {
		t.Fatalf("reopen did not retain proposal ID: %+v %v", p, err)
	}
	foreign := intent
	foreign.SessionID = "foreign-session"
	if _, err := reopened.ProposeOnce(context.Background(), foreign); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency key rebound to different session: %v", err)
	}
	foreign = intent
	foreign.SubjectID = "other-actor"
	if _, err := reopened.ProposeOnce(context.Background(), foreign); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency key rebound to another principal: %v", err)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one committed record, got %d: %v", len(files), err)
	}
	info, err := files[0].Info()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("proposal record permission is not 0600")
	}
}

func TestUnsafeAndCorruptFailClosed(t *testing.T) {
	q, dir, intent := fixture(t)
	if _, err := q.Propose(context.Background(), intent.SessionID, intent.SubjectID); !errors.Is(err, ErrLegacy) {
		t.Fatal("legacy replay proposal path must be disabled")
	}
	invalid := intent
	invalid.IdempotencyKey = "bad"
	if _, err := q.ProposeOnce(context.Background(), invalid); !errors.Is(err, ErrCorrupt) {
		t.Fatal("invalid idempotency key accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.ProposeOnce(canceled, intent); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled proposal admitted")
	}
	path := q.filename(intent.IdempotencyKey)
	if err := os.Symlink("missing-record", path); err == nil {
		if _, err := q.ProposeOnce(context.Background(), intent); !errors.Is(err, ErrCorrupt) {
			t.Fatal("symlinked record accepted")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("forged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ProposeOnce(context.Background(), intent); !errors.Is(err, ErrCorrupt) {
		t.Fatal("corrupt committed record accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrUnsafeDirectory) {
		t.Fatal("world-readable proposal directory admitted")
	}
}

type grantStore struct{ grant admission.Grant }

func (s *grantStore) Lookup(_ context.Context, id string) (admission.Grant, error) {
	if id != s.grant.ID {
		return admission.Grant{}, errors.New("grant not found")
	}
	return s.grant, nil
}

func TestControllerUsesSameDurableQueueAndRevocation(t *testing.T) {
	q, directory, _ := fixture(t)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	grants := &grantStore{grant: admission.Grant{
		ID: "grant-1", SubjectID: "actor-a", SessionID: "synthetic-session-1",
		IssuerID: "test-authority", Approved: true,
		Actions: map[admission.Operation]bool{admission.RequestReplay: true},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}}
	ctrl := controller.Controller{
		Policy: admission.Engine{Store: grants},
		Queue: q,
		Clock: func() time.Time { return now },
	}
	actor := admission.Principal{SubjectID: "actor-a", Role: admission.Agent, Authenticated: true}
	idempotencyKey := "synthetic-approval-retry-01"
	first, err := ctrl.RequestReplayOnce(context.Background(), actor, "grant-1", "synthetic-session-1", idempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	otherInstance, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	ctrl.Queue = otherInstance
	second, err := ctrl.RequestReplayOnce(context.Background(), actor, "grant-1", "synthetic-session-1", idempotencyKey)
	if err != nil || second.ProposalID != first.ProposalID {
		t.Fatalf("retry across new store instance duplicated: %+v %v", second, err)
	}
	grants.grant.Revoked = true
	if _, err := ctrl.RequestReplayOnce(context.Background(), actor, "grant-1", "synthetic-session-1", idempotencyKey); !errors.Is(err, controller.ErrDenied) {
		t.Fatal("revoked grant reissued existing proposal")
	}
}
