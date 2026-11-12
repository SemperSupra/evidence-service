// Package portfolioaccessrdte characterizes a bounded source contract.
// It is a synthetic RDT&E probe, not a credential or production policy service.
package portfolioaccessrdte

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/SemperSupra/evidence-service/pkg/admission"
)

type syntheticStore map[string]admission.Grant

func (s syntheticStore) Lookup(_ context.Context, id string) (admission.Grant, error) {
	if g, ok := s[id]; ok {
		return g, nil
	}
	return admission.Grant{}, errors.New("synthetic grant absent")
}

func syntheticGrant(actions ...admission.Operation) (admission.Engine, time.Time) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	granted := make(map[admission.Operation]bool)
	for _, action := range actions {
		granted[action] = true
	}
	g := admission.Grant{
		ID: "g-synthetic", SubjectID: "principal-1", SessionID: "workset-1",
		IssuerID: "test-owner", Approved: true, Actions: granted,
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	return admission.Engine{Store: syntheticStore{g.ID: g}}, now
}

func TestExistingScopedGrantBaseline(t *testing.T) {
	e, now := syntheticGrant(admission.InspectMetadata)
	principal := admission.Principal{SubjectID: "principal-1", Role: admission.Agent, Authenticated: true}
	good := e.Decide(context.Background(), principal, "g-synthetic", "workset-1", admission.InspectMetadata, now)
	if !good.Allowed || good.Reason != "SCOPED_GRANT" {
		t.Fatalf("expected existing scoped grant to work: %+v", good)
	}
	bad := e.Decide(context.Background(), principal, "g-synthetic", "workset-2", admission.InspectMetadata, now)
	if bad.Allowed || bad.Reason != "GRANT_NOT_FOUND_OR_SCOPE_MISMATCH" {
		t.Fatalf("cross-workset request must be denied: %+v", bad)
	}
	t.Log("FIT_BASELINE=PASS; workset scope is not an arbitrary object/resource scope")
}

func TestPolicyOnlyActionAdditionIsBlockedBySourceAllowlist(t *testing.T) {
	// A policy adds this synthetic operation to the grant, without application changes.
	newOperation := admission.Operation("publication.release.request")
	e, now := syntheticGrant(newOperation)
	principal := admission.Principal{SubjectID: "principal-1", Role: admission.Human, Authenticated: true}
	decision := e.Decide(context.Background(), principal, "g-synthetic", "workset-1", newOperation, now)
	// The negative observation is expected: it is NOT a pass of the portfolio requirement.
	if decision.Allowed || decision.Reason != "ROLE_DENIED" {
		t.Fatalf("source-fit observation changed; independently requalify the operation model: %+v", decision)
	}
	t.Log("FIT_GAP=POLICY_ONLY_NEW_ACTION_UNSUPPORTED; roleAllows in application source blocks this action")
}

func TestCustomRoleCannotBeEnabledByGrantData(t *testing.T) {
	e, now := syntheticGrant(admission.InspectMetadata)
	principal := admission.Principal{SubjectID: "principal-1", Role: admission.Role("shelf-reader"), Authenticated: true}
	decision := e.Decide(context.Background(), principal, "g-synthetic", "workset-1", admission.InspectMetadata, now)
	if decision.Allowed || decision.Reason != "ROLE_DENIED" {
		t.Fatalf("source-fit observation changed; requalify role handling: %+v", decision)
	}
	t.Log("FIT_GAP=POLICY_ONLY_NEW_ROLE_UNSUPPORTED; role switch is compiled source")
}

func TestVerifiedIssuerResourceAndRevisionNeedAdditionalContracts(t *testing.T) {
	// Reflect on the actual public surface rather than inventing unsupported access checks.
	principal := reflect.TypeOf(admission.Principal{})
	grant := reflect.TypeOf(admission.Grant{})
	for _, item := range []struct {
		typ  reflect.Type
		name string
	}{
		{principal, "Issuer"}, {principal, "Audience"}, {grant, "ResourceID"}, {grant, "PolicyRevision"},
	} {
		if _, exists := item.typ.FieldByName(item.name); exists {
			t.Fatalf("a prior fit gap changed (%s.%s); update the reference comparison", item.typ.Name(), item.name)
		}
	}
	t.Log("FIT_GAP=ISSUER_AUDIENCE_RESOURCE_POLICY_REVISION_NOT_IN_PUBLIC_CONTRACT; no effect-boundary conclusion")
}
