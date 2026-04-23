package governance

import (
	"testing"
)

func TestJurisdictionResolve(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1"})

	ctx, err := r.Resolve("Acme Corp", "Partner Inc", "john@example.com", "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if ctx.LegalRegime != "EU/GDPR" {
		t.Fatalf("expected EU/GDPR, got %s", ctx.LegalRegime)
	}
	if ctx.Entity != "Acme Corp" {
		t.Fatalf("expected Acme Corp, got %s", ctx.Entity)
	}
}

func TestJurisdictionNoRules(t *testing.T) {
	r := NewJurisdictionResolver()
	_, err := r.Resolve("Acme", "", "", "us-east-1")
	if err == nil {
		t.Fatal("expected error for region with no rules")
	}
}

func TestJurisdictionMissingFields(t *testing.T) {
	r := NewJurisdictionResolver()
	_, err := r.Resolve("", "", "", "")
	if err == nil {
		t.Fatal("expected error for missing entity/region")
	}
}

func TestJurisdictionConflictDetection(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1"})
	r.AddRule(JurisdictionRule{RuleID: "r2", LegalRegime: "UK/FCA", Region: "eu-west-1"})

	ctx, err := r.Resolve("Acme", "", "", "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx.Conflicts) == 0 {
		t.Fatal("expected jurisdiction conflict between EU/GDPR and UK/FCA")
	}
}

func TestJurisdictionWildcardRule(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "global", LegalRegime: "GLOBAL/BASE", Region: "*"})

	ctx, err := r.Resolve("Acme", "", "", "ap-southeast-1")
	if err != nil {
		t.Fatal(err)
	}
	if ctx.LegalRegime != "GLOBAL/BASE" {
		t.Fatal("wildcard rule should match any region")
	}
}

func TestJurisdictionContentHash(t *testing.T) {
	r := NewJurisdictionResolver()
	r.AddRule(JurisdictionRule{RuleID: "r1", LegalRegime: "EU/GDPR", Region: "eu-west-1"})
	ctx, _ := r.Resolve("Acme", "", "", "eu-west-1")
	if ctx.ContentHash == "" {
		t.Fatal("expected content hash")
	}
}
