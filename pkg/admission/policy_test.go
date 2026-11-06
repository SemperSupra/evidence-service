package admission

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryStore map[string]Grant

func (m memoryStore) Lookup(_ context.Context, id string) (Grant, error) {
	g, ok := m[id]
	if !ok {
		return Grant{}, errors.New("not found")
	}
	return g, nil
}
func fixture() (Engine, Principal, time.Time) {
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	return Engine{Store: memoryStore{"g1": {
		ID: "g1", SubjectID: "actor-1", SessionID: "owned-test-1",
		IssuerID: "approved-owner", Approved: true,
		Actions:   map[Operation]bool{InspectMetadata: true, StartCollection: true, RecoverSecrets: true, RequestReplay: true},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}}}, Principal{SubjectID: "actor-1", Role: Human, Authenticated: true}, now
}
func TestSharedAdmissionAndRoleBoundaries(t *testing.T) {
	engine, principal, now := fixture()
	ctx := context.Background()
	if !engine.Decide(ctx, principal, "g1", "owned-test-1", StartCollection, now).Allowed {
		t.Fatal("valid scoped human grant rejected")
	}
	if engine.Decide(ctx, principal, "g1", "owned-test-1", RecoverSecrets, now).Allowed {
		t.Fatal("ordinary human recovered session secrets")
	}
	principal.Role = Agent
	if engine.Decide(ctx, principal, "g1", "owned-test-1", StartCollection, now).Allowed || engine.Decide(ctx, principal, "g1", "owned-test-1", RecoverSecrets, now).Allowed {
		t.Fatal("agent gained capture or key privileges")
	}
	if !engine.Decide(ctx, principal, "g1", "owned-test-1", InspectMetadata, now).Allowed ||
		!engine.Decide(ctx, principal, "g1", "owned-test-1", RequestReplay, now).Allowed {
		t.Fatal("agent lost intentionally scoped proposal/metadata privileges")
	}
	principal.Role = CustodianWorker
	if !engine.Decide(ctx, principal, "g1", "owned-test-1", RecoverSecrets, now).Allowed {
		t.Fatal("approved worker rejected")
	}
	principal.Role = Custodian
	if engine.Decide(ctx, principal, "g1", "owned-test-1", Operation("arbitrary"), now).Allowed {
		t.Fatal("unknown operation granted to custodian")
	}
}
func TestNegativeScopeTimeAndRevocation(t *testing.T) {
	_, _, now := fixture()
	ctx := context.Background()
	testCases := []struct {
		name string
		edit func(*Engine, *Principal, *string, *string, *time.Time)
	}{
		{"unauthenticated", func(_ *Engine, p *Principal, _ *string, _ *string, _ *time.Time) { p.Authenticated = false }},
		{"foreign-actor", func(_ *Engine, p *Principal, _ *string, _ *string, _ *time.Time) { p.SubjectID = "other" }},
		{"foreign-session", func(_ *Engine, _ *Principal, _ *string, s *string, _ *time.Time) { *s = "other" }},
		{"wrong-grant", func(_ *Engine, _ *Principal, g *string, _ *string, _ *time.Time) { *g = "missing" }},
		{"expired", func(_ *Engine, _ *Principal, _ *string, _ *string, at *time.Time) { *at = now.Add(time.Minute) }},
		{"not-yet-valid", func(_ *Engine, _ *Principal, _ *string, _ *string, at *time.Time) { *at = now.Add(-time.Hour) }},
		{"revoked", func(e *Engine, _ *Principal, _ *string, _ *string, _ *time.Time) {
			g := e.Store.(memoryStore)["g1"]
			g.Revoked = true
			e.Store.(memoryStore)["g1"] = g
		}},
		{"not-approved", func(e *Engine, _ *Principal, _ *string, _ *string, _ *time.Time) {
			g := e.Store.(memoryStore)["g1"]
			g.Approved = false
			e.Store.(memoryStore)["g1"] = g
		}},
		{"nil-store", func(e *Engine, _ *Principal, _ *string, _ *string, _ *time.Time) { e.Store = nil }},
		{"no-scope", func(_ *Engine, _ *Principal, _ *string, s *string, _ *time.Time) { *s = "" }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, p, at := fixture()
			grantID, session := "g1", "owned-test-1"
			tc.edit(&e, &p, &grantID, &session, &at)
			if e.Decide(ctx, p, grantID, session, InspectMetadata, at).Allowed {
				t.Fatal("fail-closed negative accepted")
			}
		})
	}
}
func TestUntrustedGrantCannotAuthorize(t *testing.T) {
	e, p, now := fixture()
	g := e.Store.(memoryStore)["g1"]
	g.Actions[ViewPlaintext] = false
	e.Store.(memoryStore)["g1"] = g
	if e.Decide(context.Background(), p, "g1", "owned-test-1", ViewPlaintext, now).Allowed {
		t.Fatal("ungranted view accepted")
	}
	p.Role = Automation
	if e.Decide(context.Background(), p, "g1", "owned-test-1", ExpireEvidence, now).Allowed {
		t.Fatal("automation deleted evidence")
	}
}
