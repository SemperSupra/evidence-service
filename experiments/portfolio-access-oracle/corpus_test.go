// Package portfolioaccessoracle validates the neutral, synthetic corpus shape.
// This is not an authorization evaluator and makes no engine pass claims.
package portfolioaccessoracle

import (
	"encoding/json"
	"os"
	"testing"
)

type request struct {
	ID        string `json:"id"`
	Scenario  string `json:"scenario"`
	Principal struct {
		Kind          string `json:"kind"`
		Issuer        string `json:"issuer"`
		Subject       string `json:"subject"`
		Authenticated bool   `json:"authenticated"`
	} `json:"principal"`
	Action         string `json:"action"`
	Resource       string `json:"resource"`
	Audience       string `json:"audience"`
	PolicyRevision string `json:"policy_revision"`
	Expected       string `json:"expected"`
	Reason         string `json:"reason"`
}

type corpus struct {
	Schema string    `json:"schema"`
	Cases  []request `json:"cases"`
}

func TestSyntheticCorpusCompleteness(t *testing.T) {
	raw, err := os.ReadFile("corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != "portfolio-access-oracle/v0" {
		t.Fatalf("unknown corpus schema %q", c.Schema)
	}
	if len(c.Cases) < 18 {
		t.Fatalf("too few independent cases: %d", len(c.Cases))
	}
	seen := make(map[string]bool)
	allow, deny := 0, 0
	for _, x := range c.Cases {
		if x.ID == "" || x.Scenario == "" || x.Action == "" || x.Resource == "" || x.Reason == "" {
			t.Fatalf("incomplete case: %+v", x)
		}
		if seen[x.ID] {
			t.Fatalf("duplicate case id %q", x.ID)
		}
		seen[x.ID] = true
		if x.Principal.Kind == "" || x.Principal.Issuer == "" || x.Principal.Subject == "" {
			t.Fatalf("missing principal reference: %q", x.ID)
		}
		if x.Audience == "" || x.PolicyRevision == "" {
			t.Fatalf("missing audience/revision in case %q", x.ID)
		}
		switch x.Expected {
		case "allow":
			allow++
		case "deny":
			deny++
		default:
			t.Fatalf("invalid verdict %q in %s", x.Expected, x.ID)
		}
	}
	if allow < 4 || deny < 10 {
		t.Fatalf("insufficient positive/negative balance: allow=%d deny=%d", allow, deny)
	}
	t.Logf("CORPUS_SCHEMA=PASS; cases=%d allow=%d deny=%d; AUTHZ_ENGINE=NOT_RUN", len(c.Cases), allow, deny)
}
