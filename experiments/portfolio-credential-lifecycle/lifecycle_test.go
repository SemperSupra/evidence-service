package credentialrdte

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

type request struct {
	Workset       string
	Subject       string
	Approver      string
	RepositoryIDs []int64
	Permissions   map[string]string
}

type receipt struct {
	State       string
	Ref         string
	RequestHash string
}

type record struct {
	RequestHash string
	Ref         string
	Token       string
	Revoked     bool
}

type provider struct {
	Calls         int
	AmbiguousOnce bool
	RevokeFails   bool
	Records       map[string]record
}

func (p *provider) create(hash string) (record, error) {
	p.Calls++
	r := record{RequestHash: hash, Ref: fmt.Sprintf("synthetic-ref-%d", p.Calls), Token: fmt.Sprintf("not-a-real-token-%d", p.Calls)}
	p.Records[hash] = r
	if p.AmbiguousOnce {
		p.AmbiguousOnce = false
		return record{}, errors.New("synthetic response lost after provider create")
	}
	return r, nil
}

func (p *provider) revoke(hash string) error {
	if p.RevokeFails {
		return errors.New("synthetic provider timeout")
	}
	r, ok := p.Records[hash]
	if !ok {
		return errors.New("missing provider credential")
	}
	r.Revoked = true
	p.Records[hash] = r
	return nil
}

type broker struct {
	Provider  *provider
	ByWorkset map[string]receipt
}

func hashRequest(r request) string {
	ids := append([]int64(nil), r.RepositoryIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	r.RepositoryIDs = ids
	payload, _ := json.Marshal(r)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func scopeValid(r request) bool {
	if r.Workset == "" || r.Subject == "" || r.Approver == "" || r.Approver == r.Subject {
		return false
	}
	if len(r.RepositoryIDs) == 0 || len(r.Permissions) == 0 {
		return false
	}
	allowed := map[int64]bool{11: true, 12: true}
	seen := map[int64]bool{}
	for _, id := range r.RepositoryIDs {
		if !allowed[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	for key, level := range r.Permissions {
		if key == "contents" && (level == "read" || level == "write") {
			continue
		}
		if key == "issues" && level == "read" {
			continue
		}
		return false
	}
	return true
}

func (b *broker) mint(r request) (receipt, error) {
	if !scopeValid(r) {
		return receipt{State: "DENIED"}, errors.New("unapproved scope")
	}
	hash := hashRequest(r)
	if existing, ok := b.ByWorkset[r.Workset]; ok {
		if existing.RequestHash != hash {
			return receipt{State: "DENIED"}, errors.New("conflicting replay")
		}
		return existing, nil
	}
	created, err := b.Provider.create(hash)
	if err != nil {
		unknown := receipt{State: "UNKNOWN", RequestHash: hash}
		b.ByWorkset[r.Workset] = unknown
		return unknown, nil
	}
	active := receipt{State: "ISSUED", Ref: created.Ref, RequestHash: hash}
	b.ByWorkset[r.Workset] = active
	return active, nil
}

func (b *broker) reconcile(workset string) receipt {
	prior := b.ByWorkset[workset]
	if prior.State != "UNKNOWN" {
		return prior
	}
	r, ok := b.Provider.Records[prior.RequestHash]
	if !ok {
		return prior
	}
	if r.Revoked {
		prior.State = "REVOKED"
	} else {
		prior.State = "ISSUED"
		prior.Ref = r.Ref
	}
	b.ByWorkset[workset] = prior
	return prior
}

func (b *broker) revoke(workset string) receipt {
	prior := b.ByWorkset[workset]
	if prior.State != "ISSUED" {
		return prior
	}
	if err := b.Provider.revoke(prior.RequestHash); err != nil {
		prior.State = "UNKNOWN"
	} else {
		prior.State = "REVOKED"
	}
	b.ByWorkset[workset] = prior
	return prior
}

func setup() (*broker, request) {
	p := &provider{Records: make(map[string]record)}
	b := &broker{Provider: p, ByWorkset: make(map[string]receipt)}
	r := request{Workset: "synthetic-workset-1", Subject: "agent-1", Approver: "independent-owner", RepositoryIDs: []int64{11}, Permissions: map[string]string{"contents": "read"}}
	return b, r
}

func TestExplicitLeastPrivilegeAndApproval(t *testing.T) {
	b, r := setup()
	for name, edit := range map[string]func(*request){
		"empty-repos":   func(x *request) { x.RepositoryIDs = nil },
		"other-repo":    func(x *request) { x.RepositoryIDs = []int64{13} },
		"overscoped":    func(x *request) { x.Permissions = map[string]string{"administration": "write"} },
		"no-approval":   func(x *request) { x.Approver = "" },
		"self-approval": func(x *request) { x.Approver = x.Subject },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r
			edit(&candidate)
			got, err := b.mint(candidate)
			if err == nil || got.State != "DENIED" || b.Provider.Calls != 0 {
				t.Fatalf("invalid scope minted: %+v %v", got, err)
			}
		})
	}
	got, err := b.mint(r)
	if err != nil || got.State != "ISSUED" || got.Ref == "" || b.Provider.Calls != 1 {
		t.Fatalf("valid request failed: %+v %v", got, err)
	}
	repeated, err := b.mint(r)
	if err != nil || repeated != got || b.Provider.Calls != 1 {
		t.Fatal("idempotent retry minted extra key")
	}
	r.Permissions = map[string]string{"contents": "write"}
	denied, err := b.mint(r)
	if err == nil || denied.State != "DENIED" || b.Provider.Calls != 1 {
		t.Fatal("same-workset privilege widening accepted")
	}
	t.Log("SCOPED_MINT_AND_APPROVAL=PASS; LIVE_GITHUB_APP=NOT_RUN")
}

func TestUnknownMustReconcileAndNeverBlindRetry(t *testing.T) {
	b, r := setup()
	b.Provider.AmbiguousOnce = true
	first, err := b.mint(r)
	if err != nil || first.State != "UNKNOWN" || b.Provider.Calls != 1 {
		t.Fatalf("unknown not preserved: %+v %v", first, err)
	}
	again, err := b.mint(r)
	if err != nil || again.State != "UNKNOWN" || b.Provider.Calls != 1 {
		t.Fatal("blind retry issued another token")
	}
	reconciled := b.reconcile(r.Workset)
	if reconciled.State != "ISSUED" || reconciled.Ref == "" || b.Provider.Calls != 1 {
		t.Fatal("failed to reconcile provider outcome")
	}
	b.Provider.RevokeFails = true
	unknown := b.revoke(r.Workset)
	if unknown.State != "UNKNOWN" {
		t.Fatal("failed revocation claimed success")
	}
	b.Provider.RevokeFails = false
	if got := b.reconcile(r.Workset); got.State != "ISSUED" {
		t.Fatal("provider still-active credential mislabeled revoked")
	}
	if got := b.revoke(r.Workset); got.State != "REVOKED" {
		t.Fatal("provider-confirmed revoke missing")
	}
	t.Log("UNKNOWN_RECONCILIATION=PASS; LIVE_REVOCATION=NOT_RUN")
}

func TestReceiptsNeverCarryBearer(t *testing.T) {
	b, r := setup()
	got, err := b.mint(r)
	if err != nil {
		t.Fatal(err)
	}
	serialized, _ := json.Marshal(got)
	token := b.Provider.Records[got.RequestHash].Token
	if token == "" {
		t.Fatal("synthetic token fixture missing")
	}
	if got.Ref == token || got.RequestHash == token || strings.Contains(string(serialized), token) {
		t.Fatal("synthetic credential escaped receipt")
	}
	t.Log("OPAQUE_REFERENCE=PASS; SECRET_VAULT=NOT_RUN")
}
