package proposalstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/controller"
)

// TestProcessProposalWorker is a cooperating child process of the source-safe
// integration test. It has no network listener or privileged operations.
func TestProcessProposalWorker(t *testing.T) {
	mode := os.Getenv("EVIDENCE_TEST_CHILD_MODE")
	if mode == "" {
		t.Skip("isolated subprocess qualification helper")
	}
	if mode != "retry" && mode != "foreign" {
		t.Fatal("invalid test child mode")
	}
	directory, resultPath := os.Getenv("EVIDENCE_TEST_CHILD_STORE"), os.Getenv("EVIDENCE_TEST_CHILD_RESULT")
	if !filepath.IsAbs(directory) || !filepath.IsAbs(resultPath) {
		t.Fatal("absolute owner-controlled test paths required")
	}
	queue, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	intent := controller.ProposalIntent{
		SessionID:      "owned-synthetic-process-session",
		SubjectID:      "synthetic-actor",
		GrantID:        "approved-synthetic-grant",
		IdempotencyKey: "same-key-across-independent-processes-001",
	}
	if mode == "foreign" {
		intent.SubjectID = "foreign-synthetic-actor"
		if _, err := queue.ProposeOnce(context.Background(), intent); !errors.Is(err, ErrConflict) {
			t.Fatalf("foreign actor reused committed proposal key: %v", err)
		}
		if err := os.WriteFile(resultPath, []byte("REJECTED"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	proposal, err := queue.ProposeOnce(context.Background(), intent)
	if err != nil || !proposal.Accepted || proposal.ProposalID == "" || proposal.SessionID != intent.SessionID {
		t.Fatalf("subprocess commit/recovery failed: %+v %v", proposal, err)
	}
	if err := os.WriteFile(resultPath, []byte(proposal.ProposalID), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestProposalStoreIndependentProcessRaceAndRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL and hard-link semantics are not qualified")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "owner-only-proposals")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const processes = 10
	outputs := make([]string, processes)
	failures := make([]error, processes)
	var group sync.WaitGroup
	for n := 0; n < processes; n++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			out := filepath.Join(root, fmt.Sprintf("result-%02d", n))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, self, "-test.run=^TestProcessProposalWorker$", "-test.v=false")
			cmd.Env = append(os.Environ(), "EVIDENCE_TEST_CHILD_MODE=retry",
				"EVIDENCE_TEST_CHILD_STORE="+directory, "EVIDENCE_TEST_CHILD_RESULT="+out)
			output, err := cmd.CombinedOutput()
			if err != nil {
				failures[n] = fmt.Errorf("process %d failed: %w (%s)", n, err, strings.TrimSpace(string(output)))
				return
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				failures[n] = err
				return
			}
			outputs[n] = string(raw)
		}(n)
	}
	group.Wait()
	for n, err := range failures {
		if err != nil {
			t.Fatalf("worker %d: %v", n, err)
		}
	}
	for _, id := range outputs {
		if id == "" || id != outputs[0] {
			t.Fatalf("independent processes produced divergent proposal IDs: %q and %q", outputs[0], id)
		}
	}
	// Separate processes after the original workers exited must preserve
	// the same ID; a changed principal with the same key must still fail.
	for _, mode := range []string{"retry", "foreign"} {
		out := filepath.Join(root, "separate-"+mode)
		cmd := exec.Command(self, "-test.run=^TestProcessProposalWorker$", "-test.v=false")
		cmd.Env = append(os.Environ(), "EVIDENCE_TEST_CHILD_MODE="+mode,
			"EVIDENCE_TEST_CHILD_STORE="+directory, "EVIDENCE_TEST_CHILD_RESULT="+out)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("separate %s process failed: %v (%s)", mode, err, strings.TrimSpace(string(output)))
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		want := outputs[0]
		if mode == "foreign" {
			want = "REJECTED"
		}
		if !bytes.Equal(got, []byte(want)) {
			t.Fatalf("separate %s returned %q rather than %q", mode, got, want)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one proposal record without abandoned staging: %d, %v", len(entries), err)
	}
}
