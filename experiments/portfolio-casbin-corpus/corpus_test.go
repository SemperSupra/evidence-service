package casbincorpus

import (
	"encoding/json"
	"os"
	"testing"

	casbin "github.com/casbin/casbin/v3"
)

type sample struct {
	ID, Scenario string
	Principal    struct {
		Kind, Issuer, Subject string
		Authenticated         bool
	}
	Action, Resource, Audience string
	PolicyRevision             string `json:"policy_revision"`
	Expected                   string
}

type matrix struct {
	Schema string
	Cases  []sample
}

type state struct {
	Expired       bool
	Revoked       bool
	WorksetBound  *bool  `json:"workset_bound"`
	PolicyOverlay string `json:"policy_overlay"`
}

type states struct {
	Schema    string
	Scenarios map[string]state
}

func read(t testing.TB, path string, dst any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, dst); err != nil {
		t.Fatal(err)
	}
}

func enforcer(t testing.TB, file string) *casbin.Enforcer {
	t.Helper()
	e, err := casbin.NewEnforcer("model.conf", file)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func admitted(c sample, s state) bool {
	if !c.Principal.Authenticated || c.Principal.Subject == "" || c.Audience != "portfolio-api" {
		return false
	}
	switch c.Principal.Kind {
	case "human", "agent":
		if c.Principal.Issuer != "synthetic:oidc" {
			return false
		}
	case "automation":
		if c.Principal.Issuer != "synthetic:github-oidc" {
			return false
		}
	default:
		return false
	}
	if c.PolicyRevision != "policy-v0" && c.PolicyRevision != "policy-v1" {
		return false
	}
	return !s.Expired && !s.Revoked && (s.WorksetBound == nil || *s.WorksetBound)
}

func check(t testing.TB, c sample, ss map[string]state, engines map[string]*casbin.Enforcer) (bool, bool) {
	t.Helper()
	s := ss[c.Scenario]
	if !admitted(c, s) {
		return false, false
	}
	e := engines[c.PolicyRevision]
	if s.PolicyOverlay == "deny-reader-a" {
		e = engines["deny-v0"]
	}
	if e == nil {
		t.Fatalf("unknown policy: %s", c.PolicyRevision)
	}
	allowed, err := e.Enforce(c.Principal.Subject, c.Resource, c.Resource, c.Action)
	if err != nil {
		t.Fatal(err)
	}
	return allowed, true
}

func setup(t testing.TB) (matrix, states, map[string]*casbin.Enforcer) {
	t.Helper()
	var m matrix
	read(t, "../portfolio-access-oracle/corpus.json", &m)
	if m.Schema != "portfolio-access-oracle/v0" || len(m.Cases) != 25 {
		t.Fatalf("oracle drift: %s %d", m.Schema, len(m.Cases))
	}
	var s states
	read(t, "trust_state.json", &s)
	if s.Schema != "synthetic-trust-states/v0" {
		t.Fatal("trust fixture drift")
	}
	deny := enforcer(t, "policy_v0.csv")
	changed, err := deny.AddPolicy("reader", "shelf:a", "shelf:a", "shelf.read", "deny")
	if err != nil || !changed {
		t.Fatalf("deny fixture: %v %v", changed, err)
	}
	return m, s, map[string]*casbin.Enforcer{
		"policy-v0": enforcer(t, "policy_v0.csv"),
		"policy-v1": enforcer(t, "policy_v1.csv"),
		"deny-v0":   deny,
	}
}

func TestNeutralCorpusAgainstNativeCasbin(t *testing.T) {
	m, s, engines := setup(t)
	allow, deny, native, trust := 0, 0, 0, 0
	for _, c := range m.Cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			got, wasNative := check(t, c, s.Scenarios, engines)
			if c.Expected != "allow" && c.Expected != "deny" {
				t.Fatal("unknown verdict")
			}
			if got != (c.Expected == "allow") {
				t.Fatalf("%s mismatch: got %v expected %s", c.ID, got, c.Expected)
			}
			if got {
				allow++
			} else {
				deny++
			}
			if wasNative {
				native++
			} else {
				trust++
			}
		})
	}
	if allow != 8 || deny != 17 || native+trust != 25 {
		t.Fatalf("unexpected case totals: allow=%d deny=%d native=%d trust=%d", allow, deny, native, trust)
	}
	t.Logf("NEUTRAL_CORPUS=25/25; NATIVE_CASBIN_DECISIONS=%d; SYNTHETIC_TRUST_GATES=%d; AUTHN_CRYPTO=NOT_RUN; REVOCATION_HIL=NOT_RUN", native, trust)
}

func TestOracleMutationNegatives(t *testing.T) {
	m, s, engines := setup(t)
	var c sample
	for _, x := range m.Cases {
		if x.ID == "reader-a" {
			c = x
		}
	}
	if c.ID == "" {
		t.Fatal("baseline missing")
	}
	got, isNative := check(t, c, s.Scenarios, engines)
	if !got || !isNative {
		t.Fatal("expected native allow")
	}
	flip := c
	flip.Expected = "deny"
	got, _ = check(t, flip, s.Scenarios, engines)
	if !got || got == (flip.Expected == "allow") {
		t.Fatal("echoed oracle")
	}
	forged := c
	forged.Principal.Subject = "ungranted-other"
	got, isNative = check(t, forged, s.Scenarios, engines)
	if got || !isNative {
		t.Fatal("subject did not change native verdict")
	}
	e := enforcer(t, "policy_v0.csv")
	changed, err := e.RemovePolicy("reader", "shelf:a", "shelf:a", "shelf.read", "allow")
	if err != nil || !changed {
		t.Fatal("policy removal failed")
	}
	got, err = e.Enforce(c.Principal.Subject, c.Resource, c.Resource, c.Action)
	if err != nil || got {
		t.Fatal("policy-only removal did not deny")
	}
	t.Log("MUTATION_NEGATIVES=PASS; EXPECTED_VERDICT_ECHO=REJECTED; SUBJECT_SWAP=DENIED; POLICY_REMOVAL=DENIED")
}
