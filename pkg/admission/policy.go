// Package admission implements a fail-closed, side-effect-free decision
// primitive shared by human/AT, automation, and agent frontends.
// It does not authenticate actors, issue grants, or operate TLS collectors.
package admission

import (
	"context"
	"errors"
	"time"
)

type Role string

const (
	Human           Role = "human"
	Automation      Role = "automation"
	Agent           Role = "agent"
	Custodian       Role = "custodian"
	CustodianWorker Role = "custodian_worker"
)

type Operation string

const (
	InspectMetadata Operation = "inspect_metadata"
	RequestReplay   Operation = "request_replay"
	StartCollection Operation = "start_collection"
	ViewPlaintext   Operation = "view_plaintext"
	RecoverSecrets  Operation = "recover_secrets"
	SealEvidence    Operation = "seal_evidence"
	ExpireEvidence  Operation = "expire_evidence"
)

// Principal must come from a separately verified identity/authentication
// boundary. Never construct this from request JSON or agent tool arguments.
type Principal struct {
	SubjectID     string
	Role          Role
	Authenticated bool
}

// Grant must originate from a trusted, revocation-aware store, not the caller.
// Scope binds exact subject, session, operation and time.
type Grant struct {
	ID        string
	SubjectID string
	SessionID string
	IssuerID  string
	Approved  bool
	Revoked   bool
	Actions   map[Operation]bool
	NotBefore time.Time
	ExpiresAt time.Time
}

type GrantStore interface {
	Lookup(ctx context.Context, id string) (Grant, error)
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type Engine struct{ Store GrantStore }

func denied(reason string) Decision { return Decision{Reason: reason} }

func roleAllows(role Role, operation Operation) bool {
	switch operation {
	case InspectMetadata, RequestReplay, StartCollection, ViewPlaintext, RecoverSecrets, SealEvidence, ExpireEvidence:
	default:
		return false
	}
	switch role {
	case Human:
		return operation != RecoverSecrets
	case Automation:
		return operation != RecoverSecrets && operation != ExpireEvidence
	case Agent:
		return operation == InspectMetadata || operation == RequestReplay
	case Custodian:
		return true
	case CustodianWorker:
		return operation == InspectMetadata || operation == ViewPlaintext || operation == RecoverSecrets || operation == SealEvidence
	default:
		return false
	}
}

// Decide is fail-closed. It returns no authority token and performs no action;
// adapters must enforce the result at the actual use-of-authority boundary.
func (e Engine) Decide(ctx context.Context, principal Principal, grantID, sessionID string, action Operation, now time.Time) Decision {
	if !principal.Authenticated || principal.SubjectID == "" {
		return denied("UNAUTHENTICATED")
	}
	if !roleAllows(principal.Role, action) {
		return denied("ROLE_DENIED")
	}
	if grantID == "" || sessionID == "" || now.IsZero() || e.Store == nil {
		return denied("SCOPE_REQUIRED")
	}
	grant, err := e.Store.Lookup(ctx, grantID)
	if err != nil || grant.ID != grantID || grant.SubjectID != principal.SubjectID || grant.SessionID != sessionID {
		return denied("GRANT_NOT_FOUND_OR_SCOPE_MISMATCH")
	}
	if !grant.Approved || grant.Revoked || grant.IssuerID == "" {
		return denied("GRANT_INACTIVE")
	}
	if grant.NotBefore.IsZero() || grant.ExpiresAt.IsZero() || now.Before(grant.NotBefore) || !now.Before(grant.ExpiresAt) {
		return denied("GRANT_OUTSIDE_WINDOW")
	}
	if !grant.Actions[action] {
		return denied("OPERATION_NOT_GRANTED")
	}
	return Decision{Allowed: true, Reason: "SCOPED_GRANT"}
}

// ErrUnconfigured is available to adapters that do not yet have trusted
// identity and grant providers; they must reject admission, never fail open.
var ErrUnconfigured = errors.New("admission dependencies not configured")
