// Package portfoliocasbinrdte exercises native Casbin policy behavior on
// synthetic resources only. Authentication and effect admission are not tested.
package portfoliocasbinrdte

import (
	"testing"

	casbin "github.com/casbin/casbin/v3"
)

func load(t testing.TB, policy string) *casbin.Enforcer {
	t.Helper()
	e, err := casbin.NewEnforcer("model.conf", policy)
	if err != nil {
		t.Fatalf("load native model/policy: %v", err)
	}
	return e
}

func check(t testing.TB, e *casbin.Enforcer, subject, domain, resource, action string, want bool) {
	t.Helper()
	got, err := e.Enforce(subject, domain, resource, action)
	if err != nil {
		t.Fatalf("native Enforce returned error: %v", err)
	}
	if got != want {
		t.Fatalf("principal=%s domain=%s resource=%s action=%s: got=%t want=%t", subject, domain, resource, action, got, want)
	}
}

func TestNativeDomainAndInheritance(t *testing.T) {
	e := load(t, "policy_v0.csv")
	check(t, e, "alice", "shelf:a", "shelf:a", "shelf.read", true)
	check(t, e, "alice", "shelf:b", "shelf:b", "shelf.read", false)
	check(t, e, "bob", "shelf:a", "shelf:a", "shelf.write", true)
	check(t, e, "bob", "shelf:a", "shelf:a", "shelf.read", true) // inherited role
	check(t, e, "bob", "shelf:b", "shelf:b", "shelf.write", false)
	check(t, e, "alice", "shelf:a", "shelf:a", "shelf.destroy", false)
	t.Log("CASBIN_NATIVE=DOMAIN_INHERITANCE_AND_DEFAULT_DENY_PASS; AUTHENTICATION=NOT_RUN")
}

func TestNativeDenyOverridesExistingAllow(t *testing.T) {
	e := load(t, "policy_v0.csv")
	check(t, e, "alice", "shelf:a", "shelf:a", "shelf.read", true)
	changed, err := e.AddPolicy("reader", "shelf:a", "shelf:a", "shelf.read", "deny")
	if err != nil || !changed {
		t.Fatalf("native deny policy addition failed: changed=%v err=%v", changed, err)
	}
	check(t, e, "alice", "shelf:a", "shelf:a", "shelf.read", false)
	t.Log("CASBIN_NATIVE=EXPLICIT_DENY_PRECEDENCE_PASS; POLICY_DISTRIBUTION=NOT_RUN")
}

func TestNativePolicyOnlyVersionSwap(t *testing.T) {
	v0 := load(t, "policy_v0.csv")
	v1 := load(t, "policy_v1.csv")
	check(t, v0, "dave", "shelf:b", "shelf:b", "shelf.read", false)
	check(t, v1, "dave", "shelf:b", "shelf:b", "shelf.read", true)
	check(t, v1, "alice", "shelf:b", "shelf:b", "shelf.read", false)
	check(t, v1, "alice", "shelf:a", "shelf:a", "shelf.read", true)
	t.Log("CASBIN_NATIVE=POLICY_ONLY_DIFFERENTIAL_PASS; SIGNED_ACTIVATION_AND_REVOCATION=NOT_RUN")
}

func BenchmarkNativeReadDecision(b *testing.B) {
	e := load(b, "policy_v0.csv")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := e.Enforce("alice", "shelf:a", "shelf:a", "shelf.read")
		if err != nil || !ok {
			b.Fatalf("invalid benchmark verdict: allow=%v err=%v", ok, err)
		}
	}
}
