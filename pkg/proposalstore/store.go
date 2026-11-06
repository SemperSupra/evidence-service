// Package proposalstore provides an owner-private, source-safe file-backed
// replay-PROPOSAL queue. It never initiates replay or decrypts evidence.
// Filesystem power-loss/crash consistency and hostile local users are not
// qualified; see docs/PROPOSALSTORE.md before choosing a production backend.
package proposalstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/SemperSupra/evidence-service/pkg/controller"
)

const maxRecord = 4096

var (
	ErrUnsafeDirectory = errors.New("proposal store requires owner-private directory")
	ErrConflict = errors.New("idempotency key already bound to another scope")
	ErrCorrupt = errors.New("proposal record corrupt or unsafe")
	ErrLegacy = errors.New("non-idempotent proposal path disabled")
)

var token = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

type Store struct{ directory string }

type record struct {
	Intent controller.ProposalIntent `json:"intent"`
	Proposal controller.ReplayProposal `json:"proposal"`
}

// Open requires a precreated private directory. It never chmods or replaces
// a caller-selected path and never follows symlinks at the directory itself.
func Open(directory string) (*Store, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return nil, ErrUnsafeDirectory
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnsafeDirectory
	}
	return &Store{directory: directory}, nil
}

func (*Store) Propose(context.Context, string, string) (controller.ReplayProposal, error) {
	return controller.ReplayProposal{}, ErrLegacy
}

func valid(i controller.ProposalIntent) bool {
	return token.MatchString(i.IdempotencyKey) &&
		len(i.SessionID) > 0 && len(i.SessionID) <= 256 &&
		len(i.SubjectID) > 0 && len(i.SubjectID) <= 256 &&
		len(i.GrantID) > 0 && len(i.GrantID) <= 256
}

func (s *Store) filename(key string) string {
	sum := sha256.Sum256([]byte("evidence-service:proposal-idempotency:v1:" + key))
	return filepath.Join(s.directory, hex.EncodeToString(sum[:])+".json")
}

func (s *Store) read(path string, wanted controller.ProposalIntent) (controller.ReplayProposal, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() <= 0 || info.Size() > maxRecord {
		return controller.ReplayProposal{}, ErrCorrupt
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return controller.ReplayProposal{}, ErrCorrupt
	}
	var r record
	if err := json.Unmarshal(bytes, &r); err != nil || !valid(r.Intent) ||
		r.Proposal.ProposalID == "" || !r.Proposal.Accepted ||
		r.Proposal.SessionID != r.Intent.SessionID {
		return controller.ReplayProposal{}, ErrCorrupt
	}
	if r.Intent != wanted {
		return controller.ReplayProposal{}, ErrConflict
	}
	return r.Proposal, nil
}

// ProposeOnce uses atomic same-filesystem hard-link publication to win an
// idempotency key exactly once even across cooperating processes. A competing
// writer reads the already committed scoped proposal. This does not qualify
// abrupt host-power-loss durability, mutable hostile filesystems, or NFS.
func (s *Store) ProposeOnce(ctx context.Context, intent controller.ProposalIntent) (controller.ReplayProposal, error) {
	if err := ctx.Err(); err != nil {
		return controller.ReplayProposal{}, err
	}
	if !valid(intent) {
		return controller.ReplayProposal{}, ErrCorrupt
	}
	if _, err := Open(s.directory); err != nil {
		return controller.ReplayProposal{}, err
	}
	path := s.filename(intent.IdempotencyKey)
	if _, err := os.Lstat(path); err == nil {
		return s.read(path, intent)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return controller.ReplayProposal{}, ErrCorrupt
	}

	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return controller.ReplayProposal{}, errors.New("cannot create proposal identity")
	}
	proposal := controller.ReplayProposal{
		ProposalID: "proposal-" + hex.EncodeToString(id),
		SessionID: intent.SessionID,
		Accepted: true,
	}
	raw, err := json.Marshal(record{Intent: intent, Proposal: proposal})
	if err != nil || len(raw) > maxRecord {
		return controller.ReplayProposal{}, ErrCorrupt
	}
	stage, err := os.CreateTemp(s.directory, ".proposal-stage-")
	if err != nil {
		return controller.ReplayProposal{}, err
	}
	defer os.Remove(stage.Name())
	if _, err := stage.Write(raw); err != nil {
		_ = stage.Close()
		return controller.ReplayProposal{}, err
	}
	if err := stage.Sync(); err != nil {
		_ = stage.Close()
		return controller.ReplayProposal{}, err
	}
	if err := stage.Close(); err != nil {
		return controller.ReplayProposal{}, err
	}
	if err := ctx.Err(); err != nil {
		return controller.ReplayProposal{}, err
	}
	if err := os.Link(stage.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return s.read(path, intent)
		}
		return controller.ReplayProposal{}, err
	}
	if dir, err := os.Open(s.directory); err == nil {
		_ = dir.Sync() // best effort; crash/power-loss durability is not claimed
		_ = dir.Close()
	}
	return proposal, nil
}
