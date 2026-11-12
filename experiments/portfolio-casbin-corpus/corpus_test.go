// Package casbincorpus is a source-safe harness for native Casbin policy evaluation.
// It is not a JWT validator, live grant store, broker, PDP service, or production identity boundary.
package casbincorpus

import (
 "encoding/json"
 "fmt"
 "os"
 "testing"

 casbin "github.com/casbin/casbin/v3"
)

type fixtureCase struct {
 ID string `json:"id"`
 Scenario string `json:"scenario"`
 Principal struct {
  Kind string `json:"kind"`
  Issuer string `json:"issuer"`
  Subject string `json:"subject"`
  Authenticated bool `json:"authenticated"`
 } `json:"principal"`
 Action string `json:"action"`
 Resource string `json:"resource"`
 Audience string `json:"audience"`
 PolicyRevision string `json:"policy_revision"`
 Expected string `json:"expected"`
}
type corpus struct {
 Schema string `json:"schema"`
 Cases []fixtureCase `json:"cases"`
}
type trustState struct {
 Expired bool `json:"expired"`
 Revoked bool `json:"revoked"`
 WorksetBound *bool `json:"workset_bound"`
 PolicyOverlay string `json:"policy_overlay"`
}
type trustCorpus struct {
 Schema string `json:"schema"`
 Scenarios map[string]trustState `json:"scenarios"`
}
func readJSON(t testing.TB, path string, target any) {
 t.Helper()
 raw, err := os.ReadFile(path)
 if err != nil { t.Fatal(err) }
 if err := json.Unmarshal(raw, target); err != nil { t.Fatal(err) }
}
func native(t testing.TB, file string) *casbin.Enforcer {
 t.Helper()
 e, err := casbin.NewEnforcer("model.conf", file)
 if err != nil { t.Fatal(err) }
 return e
}
// preflight models upstream *verified* claims and lease facts using wholly synthetic inputs.
// No cryptographic identity, signature, grant or expiry verification is performed here.
func preflight(c fixtureCase, state trustState) bool {
 if !c.Principal.Authenticated || c.Principal.Subject == "" || c.Audience != "portfolio-api" { return false }
 switch c.Principal.Kind {
 case "human", "agent":
  if c.Principal.Issuer != "synthetic:oidc" { return false }
 case "automation":
  if c.Principal.Issuer != "synthetic:github-oidc" { return false }
 default:
  return false
 }
 if c.PolicyRevision != "policy-v0" && c.PolicyRevision != "policy-v1" { return false }
 if state.Expired || state.Revoked || (state.WorksetBound != nil && !*state.WorksetBound) { return false }
 return true
}
func evaluate(t testing.TB, c fixtureCase, states map[string]trustState, engines map[string]*casbin.Enforcer) (bool, string) {
 t.Helper()
 state := states[c.Scenario]
 if !preflight(c, state) { return false, "SYNTHETIC_TRUST_GATE" }
 engine := engines[c.PolicyRevision]
 if state.PolicyOverlay == "deny-reader-a" { engine = engines["deny-v0"] }
 if engine == nil { t.Fatalf("unsupported policy revision %q", c.PolicyRevision) }
 // Access-control semantics are evaluated by native Casbin policies, not by case ID.
 allowed, err := engine.Enforce(c.Principal.Subject, c.Resource, c.Resource, c.Action)
 if err != nil { t.Fatalf("native Casbin enforcement error: %v", err) }
 return allowed, "NATIVE_CASBIN"
}
func setup(t testing.TB) (corpus, trustCorpus, map[string]*casbin.Enforcer) {
 t.Helper()
 var c corpus
 readJSON(t, "../portfolio-access-oracle/corpus.json", &c)
 if c.Schema != "portfolio-access-oracle/v0" || len(c.Cases) != 25 { t.Fatalf("unapproved neutral fixture: %s / %d", c.Schema, len(c.Cases)) }
 var s trustCorpus
 readJSON(t, "trust_state.json", &s)
 if s.Schema != "synthetic-trust-states/v0" { t.Fatalf("unapproved synthetic trust schema: %s", s.Schema) }
 deny := native(t, "policy_v0.csv")
 if changed, err := deny.AddPolicy("reader", "shelf:a", "shelf:a", "shelf.read", "deny"); err != nil || !changed {
  t.Fatalf("native policy overlay failed: %t %v", changed, err)
 }
 return c, s, map[string]*casbin.Enforcer{
  "policy-v0": native(t, "policy_v0.csv"),
  "policy-v1": native(t, "policy_v1.csv"),
  "deny-v0": deny,
 }
}
func TestNeutralCorpusAgainstNativeCasbin(t *testing.T) {
 c, states, engines := setup(t)
 allows, denies, nativeCount, syntheticCount := 0, 0, 0, 0
 for _, sample := range c.Cases {
  sample := sample
  t.Run(sample.ID, func(t *testing.T) {
   allowed, origin := evaluate(t, sample, states.Scenarios, engines)
   want := sample.Expected == "allow"
   if sample.Expected != "allow" && sample.Expected != "deny" { t.Fatalf("invalid expected verdict") }
   if allowed != want { t.Fatalf("fixture mismatch: scenario=%s principal=%s resource=%s action=%s got=%v want=%v origin=%s",sample.Scenario,sample.Principal.Subject,sample.Resource,sample.Action,allowed,want,origin) }
   if allowed { allows++ } else { denies++ }
   if origin=="NATIVE_CASBIN" { nativeCount++ } else { syntheticCount++ }
  })
 }
 if allows != 8 || denies != 17 { t.Fatalf("outcome drift: allow=%d deny=%d",allows,denies) }
 t.Logf("NEUTRAL_CORPUS=25/25; NATIVE_CASBIN_DECISIONS=%d; SYNTHETIC_TRUST_GATES=%d; AUTHN_CRYPTO=NOT_RUN; REVOCATION_HIL=NOT_RUN",nativeCount,syntheticCount)
}
func TestOracleIsNotEchoedOrCaseIDDriven(t *testing.T) {
 c, states, engines := setup(t)
 var baseline fixtureCase
 for _, v := range c.Cases { if v.ID=="reader-a" { baseline=v; break } }
 if baseline.ID=="" { t.Fatal("missing reference case") }
 actual, origin := evaluate(t,baseline,states.Scenarios,engines)
 if !actual || origin!="NATIVE_CASBIN" { t.Fatalf("baseline unexpectedly denied: %v %s",actual,origin) }
 // Falsify an oracle verdict: native evaluation must remain ALLOW.
 corrupt := baseline
 corrupt.Expected="deny"
 result,_:=evaluate(t,corrupt,states.Scenarios,engines)
 if !result || result==(corrupt.Expected=="allow") { t.Fatal("candidate appears to echo expected verdict") }
 // Rewrite subject while preserving case ID and oracle: native engine must DENY.
 forged:=baseline
 forged.Principal.Subject="ungranted-other"
 result,origin=evaluate(t,forged,states.Scenarios,engines)
 if result || origin!="NATIVE_CASBIN" { t.Fatalf("case-ID keyed or false permit: %t %s",result,origin) }
 // A real policy data change, not a code change, removes the reader allow.
 e:=native(t,"policy_v0.csv")
 changed,err:=e.RemovePolicy("reader","shelf:a","shelf:a","shelf.read","allow")
 if err!=nil || !changed { t.Fatalf("remove policy failed: %t %v",changed,err) }
 policyAllow,err:=e.Enforce(baseline.Principal.Subject,baseline.Resource,baseline.Resource,baseline.Action)
 if err!=nil || policyAllow { t.Fatalf("policy removal did not deny: %t %v",policyAllow,err) }
 t.Log(fmt.Sprintf("MUTATION_NEGATIVES=PASS; EXPECTED_VERDICT_ECHO=REJECTED; SUBJECT_SWAP=DENIED; POLICY_REMOVAL=DENIED"))
}
