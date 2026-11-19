package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/admission"
	"github.com/SemperSupra/evidence-service/pkg/attestation"
	"github.com/SemperSupra/evidence-service/pkg/controller"
	"github.com/SemperSupra/evidence-service/pkg/proposalstore"
)

// Research-only BrowserParity-shaped exact-scope test. This is NOT a new
// production issuer, evidence receiver, browser adapter or trusted grant store.
type ownedManifest struct {
	Schema       string `json:"schema"`
	SessionID    string `json:"session_id"`
	Generation   uint64 `json:"generation"`
	TabID        string `json:"tab_id"`
	Origin       string `json:"origin"`
	Realm        string `json:"realm"`
	Catalog      string `json:"catalog"`
	RequestID    string `json:"request_id"`
	ArtifactHash string `json:"artifact_sha256"`
}

type externalFixtureGrant struct{ grant admission.Grant }

func (s *externalFixtureGrant) Lookup(_ context.Context, id string) (admission.Grant, error) {
	if id != s.grant.ID {
		return admission.Grant{}, errors.New("no separately trusted grant")
	}
	return s.grant, nil
}

type syntheticOwner struct {
	expected ownedManifest
	public   ed25519.PublicKey
	private  ed25519.PrivateKey
	signer   string
	store    *externalFixtureGrant
	engine   admission.Engine
	actor    admission.Principal
	now      time.Time
}

func setup(t *testing.T) syntheticOwner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	g := &externalFixtureGrant{grant: admission.Grant{
		ID: "synthetic-operator-grant-0001", SubjectID: "owned-actor",
		SessionID: "owned-session", IssuerID: "fixture-out-of-band-issuer",
		Approved: true, Actions: map[admission.Operation]bool{
			admission.InspectMetadata: true, admission.RequestReplay: true,
		},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}}
	return syntheticOwner{
		expected: ownedManifest{
			Schema: "bp-owned-evidence-consumer/v1", SessionID: "owned-session",
			Generation: 17, TabID: "owned-tab-A", Origin: "http://127.0.0.1",
			Realm: "synthetic-chat", Catalog: "owned-v1",
			RequestID: "synthetic-request-01",
			ArtifactHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		public: pub, private: priv, signer: "synthetic-independent-reviewer",
		store: g, engine: admission.Engine{Store: g},
		actor: admission.Principal{SubjectID: "owned-actor", Role: admission.Agent, Authenticated: true},
		now: now,
	}
}

func (s syntheticOwner) sign(t *testing.T, m ownedManifest) ([]byte, attestation.Receipt) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := attestation.Sign(raw, s.signer, s.private)
	if err != nil {
		t.Fatal(err)
	}
	return raw, receipt
}

// A consumer must bind both the exact independently signed bytes and the
// separately obtained scope. The shared admission.Engine alone does not carry
// BrowserParity's selected-tab, generation, realm, catalog or request identity.
func (s syntheticOwner) accept(raw []byte, receipt attestation.Receipt, principal admission.Principal, action admission.Operation) error {
	if receipt.SignerID != s.signer {
		return errors.New("wrong externally trusted signer identity")
	}
	if err := attestation.Verify(raw, receipt, s.public); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var got ownedManifest
	if err := decoder.Decode(&got); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("extra JSON content")
	}
	canonical, err := json.Marshal(got)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("noncanonical or ambiguous source envelope")
	}
	if got != s.expected {
		return errors.New("foreign tab, generation, session, origin, action or artifact identity")
	}
	if !s.engine.Decide(context.Background(), principal, s.store.grant.ID, s.expected.SessionID, action, s.now).Allowed {
		return errors.New("separately trusted grant denied")
	}
	return nil
}

func TestExactSignedSelectedTabScopeAndThreeAudiences(t *testing.T) {
	s := setup(t)
	raw, sig := s.sign(t, s.expected)
	for _, role := range []admission.Role{admission.Human, admission.Automation, admission.Agent} {
		t.Run(string(role), func(t *testing.T) {
			p := s.actor
			p.Role = role
			if err := s.accept(raw, sig, p, admission.InspectMetadata); err != nil {
				t.Fatalf("valid metadata-only source composition denied: %v", err)
			}
			if s.engine.Decide(context.Background(), p, s.store.grant.ID, s.expected.SessionID, admission.RecoverSecrets, s.now).Allowed {
				t.Fatal("non-custodian recovered keys from metadata grant")
			}
		})
	}
}

func TestFreshValidSignatureDoesNotOverrideForeignTabOrGeneration(t *testing.T) {
	cases := map[string]func(*ownedManifest){
		"adjacent-tab": func(x *ownedManifest) { x.TabID = "owned-tab-B" },
		"old-generation": func(x *ownedManifest) { x.Generation-- },
		"foreign-origin": func(x *ownedManifest) { x.Origin = "https://example.invalid" },
		"stale-catalog": func(x *ownedManifest) { x.Catalog = "old" },
		"foreign-realm": func(x *ownedManifest) { x.Realm = "other" },
		"foreign-request": func(x *ownedManifest) { x.RequestID = "replay" },
		"artifact-change": func(x *ownedManifest) { x.ArtifactHash = "0000000000000000000000000000000000000000000000000000000000000000" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := setup(t)
			m := s.expected
			edit(&m)
			raw, sig := s.sign(t, m)
			if err := attestation.Verify(raw, sig, s.public); err != nil {
				t.Fatalf("the modified artifact was independently signed: %v", err)
			}
			// An ordinary evidence-service session grant lacks a tab/generation
			// argument and therefore cannot alone close this BrowserParity gap.
			if !s.engine.Decide(context.Background(), s.actor, s.store.grant.ID, s.expected.SessionID, admission.InspectMetadata, s.now).Allowed {
				t.Fatal("test precondition: ordinary session grant should still be in force")
			}
			if err := s.accept(raw, sig, s.actor, admission.InspectMetadata); err == nil {
				t.Fatal("valid signature and session grant bypassed exact BrowserParity operation scope")
			}
		})
	}
}

func TestSignaturesCannotSelfGrantOrSupplyTrustRoot(t *testing.T) {
	s := setup(t)
	raw, sig := s.sign(t, s.expected)
	if err := s.accept(raw, sig, s.actor, admission.InspectMetadata); err != nil {
		t.Fatal(err)
	}
	t.Run("altered-after-signing", func(t *testing.T) {
		if err := s.accept(append(bytes.Clone(raw), ' '), sig, s.actor, admission.InspectMetadata); err == nil {
			t.Fatal("changed bytes were accepted")
		}
	})
	t.Run("wrong-trusted-key", func(t *testing.T) {
		foreign := setup(t)
		foreign.expected = s.expected
		foreign.store = s.store
		foreign.engine = s.engine
		foreign.now = s.now
		if err := foreign.accept(raw, sig, s.actor, admission.InspectMetadata); err == nil {
			t.Fatal("untrusted source receipt selected its own verification key")
		}
	})
	t.Run("wrong-claimed-signer", func(t *testing.T) {
		forged := sig
		forged.SignerID = "other-signer"
		if err := s.accept(raw, forged, s.actor, admission.InspectMetadata); err == nil {
			t.Fatal("self-claimed signer identity accepted")
		}
	})
	t.Run("signed-duplicate-json-fields", func(t *testing.T) {
		dup := bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"bp-owned-evidence-consumer/v1","schema":`), 1)
		reReceipt, err := attestation.Sign(dup, s.signer, s.private)
		if err != nil { t.Fatal(err) }
		// Correct signature over ambiguous bytes is not a canonical data model.
		if err := attestation.Verify(dup, reReceipt, s.public); err != nil { t.Fatal(err) }
		if err := s.accept(dup, reReceipt, s.actor, admission.InspectMetadata); err == nil {
			t.Fatal("signed duplicate JSON keys crossed an exact receiver contract")
		}
	})
}

func TestRevocationExpiryAndUntrustedPrincipalBlockComposedAdmission(t *testing.T) {
	tests := []struct {
		name string
		change func(*syntheticOwner)
	}{
		{"no-grant-store", func(s *syntheticOwner) { s.engine.Store = nil }},
		{"revoked", func(s *syntheticOwner) { s.store.grant.Revoked = true }},
		{"not-approved", func(s *syntheticOwner) { s.store.grant.Approved = false }},
		{"issuer-absent", func(s *syntheticOwner) { s.store.grant.IssuerID = "" }},
		{"expired", func(s *syntheticOwner) { s.now = s.now.Add(time.Hour) }},
		{"foreign-actor", func(s *syntheticOwner) { s.actor.SubjectID = "other" }},
		{"unauthenticated", func(s *syntheticOwner) { s.actor.Authenticated = false }},
		{"other-session", func(s *syntheticOwner) { s.store.grant.SessionID = "other" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := setup(t)
			raw, sig := s.sign(t, s.expected)
			tc.change(&s)
			if err := s.accept(raw, sig, s.actor, admission.InspectMetadata); err == nil {
				t.Fatal("signed content admitted without independent valid grant")
			}
		})
	}
}

func TestIdempotentProposalIsNotBrowserEffectAndRevocationStillWins(t *testing.T) {
	s := setup(t)
	dir := filepath.Join(t.TempDir(), "owner-private-proposals")
	if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
	store, err := proposalstore.Open(dir)
	if err != nil { t.Fatal(err) }
	c := controller.Controller{
		Policy: s.engine, Queue: store,
		Clock: func() time.Time { return s.now },
	}
	raw, sig := s.sign(t, s.expected)
	if err := s.accept(raw, sig, s.actor, admission.RequestReplay); err != nil { t.Fatal(err) }
	const key = "bp-r083-synthetic-idempotency-01"
	a, err := c.RequestReplayOnce(context.Background(), s.actor, s.store.grant.ID, s.expected.SessionID, key)
	if err != nil || a.ProposalID == "" || !a.Accepted { t.Fatalf("proposal only: %+v %v", a, err) }
	b, err := c.RequestReplayOnce(context.Background(), s.actor, s.store.grant.ID, s.expected.SessionID, key)
	if err != nil || b.ProposalID != a.ProposalID { t.Fatal("replay proposal duplicated") }
	s.store.grant.Revoked = true
	if _, err := c.RequestReplayOnce(context.Background(), s.actor, s.store.grant.ID, s.expected.SessionID, key); !errors.Is(err, controller.ErrDenied) {
		t.Fatal("revoked grant was allowed to access even a previous idempotent proposal")
	}
	records, err := os.ReadDir(dir)
	if err != nil || len(records) != 1 {
		t.Fatalf("expected a single durable proposal record, got %d %v", len(records), err)
	}
	// This receipt explicitly has no navigation/click/remote effects.
	t.Logf("BP_R083_SOURCE_PRIMITIVE_RECEIPT=arch:%s;signature:PASS;external_scope:PASS;idempotent_proposal:PASS;effect:NOT_EXECUTED;issuer:HIL_UNQUALIFIED;promotion:false", runtime.GOARCH)
}
