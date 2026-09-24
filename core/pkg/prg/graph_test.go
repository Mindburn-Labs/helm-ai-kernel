package prg

import (
	"encoding/hex"
	"strings"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
)

// --- Graph ---

func TestNewGraph_NotNil(t *testing.T) {
	g := NewGraph()
	if g == nil {
		t.Fatal("nil")
	}
}

func TestNewGraph_EmptyRules(t *testing.T) {
	g := NewGraph()
	if len(g.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(g.Rules))
	}
}

func TestGraph_AddRule(t *testing.T) {
	g := NewGraph()
	err := g.AddRule("act-1", RequirementSet{ID: "rs-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g.Rules["act-1"]; !ok {
		t.Fatal("rule not added")
	}
}

func TestGraph_AddRule_Overwrites(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-1", RequirementSet{ID: "rs-1"})
	_ = g.AddRule("act-1", RequirementSet{ID: "rs-2"})
	if g.Rules["act-1"].ID != "rs-2" {
		t.Fatal("expected overwrite")
	}
}

func TestGraph_ContentHash_Empty(t *testing.T) {
	g := NewGraph()
	h, err := g.ContentHash()
	if err != nil {
		t.Fatal(err)
	}
	if h != "" {
		t.Fatal("expected empty hash for empty graph")
	}
}

func TestGraph_ContentHash_NotEmpty(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-1", RequirementSet{ID: "rs-1"})
	h, err := g.ContentHash()
	if err != nil {
		t.Fatal(err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestGraph_ContentHash_Deterministic(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-1", RequirementSet{ID: "rs-1"})
	_ = g.AddRule("act-2", RequirementSet{ID: "rs-2"})
	h1, _ := g.ContentHash()
	h2, _ := g.ContentHash()
	if h1 != h2 {
		t.Fatal("expected deterministic hash")
	}
}

func TestGraph_ContentHash_DifferentRules_DifferentHash(t *testing.T) {
	g1 := NewGraph()
	_ = g1.AddRule("act-1", RequirementSet{ID: "rs-1"})
	g2 := NewGraph()
	_ = g2.AddRule("act-1", RequirementSet{ID: "rs-2"})
	h1, _ := g1.ContentHash()
	h2, _ := g2.ContentHash()
	if h1 == h2 {
		t.Fatal("different rules should produce different hashes")
	}
}

func TestGraph_ContentHash_OrderIndependent(t *testing.T) {
	g1 := NewGraph()
	_ = g1.AddRule("a", RequirementSet{ID: "r1"})
	_ = g1.AddRule("b", RequirementSet{ID: "r2"})
	g2 := NewGraph()
	_ = g2.AddRule("b", RequirementSet{ID: "r2"})
	_ = g2.AddRule("a", RequirementSet{ID: "r1"})
	h1, _ := g1.ContentHash()
	h2, _ := g2.ContentHash()
	if h1 != h2 {
		t.Fatal("insertion order should not affect hash")
	}
}

func TestGraph_BindByCapability(t *testing.T) {
	g := NewGraph()
	err := g.BindByCapability("cap-1", RequirementSet{ID: "rs-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g.Rules["cap-1"]; !ok {
		t.Fatal("capability not bound")
	}
}

func TestGraph_Validate_NoRule_ReturnsError(t *testing.T) {
	g := NewGraph()
	_, _, err := g.Validate("unknown", nil)
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestGraph_Validate_EmptyReqs_ReturnsTrue(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-1", RequirementSet{ID: "rs-1"})
	ok, _, err := g.Validate("act-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("empty requirement set should pass")
	}
}

func TestGraph_Validate_ArtifactPresent(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-1", RequirementSet{
		ID:    "rs-1",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", ArtifactType: "evidence/alert"},
		},
	})
	arts := []*pkg_artifact.ArtifactEnvelope{{Type: "evidence/alert"}}
	ok, hash, err := g.Validate("act-1", arts)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected pass")
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestGraph_Validate_ArtifactMissing(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-1", RequirementSet{
		ID:    "rs-1",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", ArtifactType: "evidence/alert"},
		},
	})
	arts := []*pkg_artifact.ArtifactEnvelope{{Type: "evidence/other"}}
	ok, _, err := g.Validate("act-1", arts)
	if err == nil && ok {
		t.Fatal("expected failure when artifact missing")
	}
}

func TestGraph_Validate_EmptyLogicDefaultsToAND(t *testing.T) {
	g := NewGraph()
	// Logic unset ("") must behave as AND, matching the canonical CEL path,
	// not fall through to the fail-safe deny.
	_ = g.AddRule("act-1", RequirementSet{
		ID:           "rs-1",
		Requirements: []Requirement{{ID: "r1", ArtifactType: "evidence/alert"}},
	})
	arts := []*pkg_artifact.ArtifactEnvelope{{Type: "evidence/alert"}}
	ok, _, err := g.Validate("act-1", arts)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("empty logic with satisfied requirement should pass (AND semantics)")
	}
}

func TestGraph_Validate_NOTLogic(t *testing.T) {
	g := NewGraph()
	// NOT is satisfied unless every child/leaf is satisfied.
	_ = g.AddRule("act-not", RequirementSet{
		ID:           "rs-not",
		Logic:        NOT,
		Requirements: []Requirement{{ID: "r1", ArtifactType: "evidence/forbidden"}},
	})

	// Artifact absent → leaf false → NOT true → pass.
	ok, _, err := g.Validate("act-not", []*pkg_artifact.ArtifactEnvelope{{Type: "evidence/other"}})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("NOT with unsatisfied leaf should pass")
	}

	// Artifact present → leaf true → NOT false → deny.
	ok, _, err = g.Validate("act-not", []*pkg_artifact.ArtifactEnvelope{{Type: "evidence/forbidden"}})
	if err == nil && ok {
		t.Fatal("NOT with satisfied leaf should deny")
	}
}

// --- RequirementSet.Hash ---

func TestRequirementSet_Hash_NotEmpty(t *testing.T) {
	rs := RequirementSet{ID: "rs-1", Logic: AND}
	h := rs.Hash()
	if h == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestRequirementSet_Hash_IsFixedWidthDigest(t *testing.T) {
	// The hash is bound into DecisionRecord.RequirementSetHash; it must be a
	// real content-addressed digest (sha256:<64 hex>), not a hex dump of the
	// raw, unbounded content string.
	rs := RequirementSet{
		ID:    "rs-1",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", Expression: "input.action == 'deploy' && size(input.artifacts) > 0"},
			{ID: "r2", ArtifactType: "attestation"},
		},
		Children: []RequirementSet{{ID: "child", Logic: OR}},
	}
	h := rs.Hash()
	const prefix = "sha256:"
	if !strings.HasPrefix(h, prefix) {
		t.Fatalf("expected %q prefix, got %q", prefix, h)
	}
	hexPart := strings.TrimPrefix(h, prefix)
	if len(hexPart) != 64 {
		t.Fatalf("expected 64 hex chars (32-byte digest), got %d: %q", len(hexPart), hexPart)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Fatalf("digest is not valid hex: %v", err)
	}
}

func TestRequirementSet_Hash_Deterministic(t *testing.T) {
	rs := RequirementSet{ID: "rs-1", Logic: AND, Requirements: []Requirement{{ID: "r1", Expression: "true"}}}
	h1 := rs.Hash()
	h2 := rs.Hash()
	if h1 != h2 {
		t.Fatal("hash should be deterministic")
	}
}

func TestRequirementSet_Hash_DifferentID_DifferentHash(t *testing.T) {
	rs1 := RequirementSet{ID: "a"}
	rs2 := RequirementSet{ID: "b"}
	if rs1.Hash() == rs2.Hash() {
		t.Fatal("different IDs should produce different hashes")
	}
}

func TestRequirementSet_Hash_IncludesChildren(t *testing.T) {
	rs1 := RequirementSet{ID: "x"}
	rs2 := RequirementSet{ID: "x", Children: []RequirementSet{{ID: "child"}}}
	if rs1.Hash() == rs2.Hash() {
		t.Fatal("children should affect hash")
	}
}

// --- Compiler ---

func TestNewCompiler_NotNil(t *testing.T) {
	c, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("nil")
	}
}

func TestCompiler_Compile_ReturnsGraph(t *testing.T) {
	c, _ := NewCompiler()
	g, err := c.Compile(RequirementSet{ID: "rs-1"})
	if err != nil {
		t.Fatal(err)
	}
	if g == nil {
		t.Fatal("nil graph")
	}
}

func TestCompiler_Compile_ContainsRule(t *testing.T) {
	c, _ := NewCompiler()
	g, _ := c.Compile(RequirementSet{ID: "rs-1"})
	if _, ok := g.Rules["rs-1"]; !ok {
		t.Fatal("compiled graph should contain rule with ID as key")
	}
}

// Graph.Validate evaluates artifact presence only. Before this guard, a
// requirement carrying a CEL Expression but no ArtifactType was assumed
// satisfied, so Validate could return true *plus a rule hash* for a policy
// whose expression was never evaluated — a fail-open verdict carrying evidence
// of an evaluation that did not happen.
func TestGraph_Validate_RefusesCELExpressionRequirement(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-cel", RequirementSet{
		ID:    "rs-cel",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", Expression: "intent.risk < 3"},
		},
	})

	ok, hash, err := g.Validate("act-cel", nil)
	if err == nil {
		t.Fatal("expected Validate to refuse a CEL expression requirement")
	}
	if ok {
		t.Fatal("fail-open: reported satisfied without evaluating the expression")
	}
	if hash != "" {
		t.Fatalf("must not emit a rule hash for an unevaluated rule, got %q", hash)
	}
	if !strings.Contains(err.Error(), "authority.Decide") {
		t.Fatalf("error should name the canonical evaluator, got %q", err)
	}
}

// The guard must see expressions nested in child sets, not just top-level ones.
func TestGraph_Validate_RefusesNestedCELExpressionRequirement(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-nested", RequirementSet{
		ID:    "rs-root",
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", ArtifactType: "evidence/alert"},
		},
		Children: []RequirementSet{{
			ID:           "rs-child",
			Logic:        AND,
			Requirements: []Requirement{{ID: "r2", Expression: "state.approved == true"}},
		}},
	})

	arts := []*pkg_artifact.ArtifactEnvelope{{Type: "evidence/alert"}}
	ok, _, err := g.Validate("act-nested", arts)
	if err == nil || ok {
		t.Fatal("expected a nested CEL expression requirement to be refused")
	}
}

// A requirement with neither an ArtifactType nor an Expression is malformed.
// It must fail closed rather than count as satisfied.
func TestGraph_Validate_MalformedRequirementFailsClosed(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-malformed", RequirementSet{
		ID:           "rs-malformed",
		Logic:        AND,
		Requirements: []Requirement{{ID: "r1", Description: "no artifact type, no expression"}},
	})

	ok, _, err := g.Validate("act-malformed", nil)
	if ok {
		t.Fatal("fail-open: malformed requirement counted as satisfied")
	}
	if err == nil {
		t.Fatal("expected an error for an unsatisfiable rule")
	}
	if !strings.Contains(err.Error(), "action act-malformed has malformed requirement") {
		t.Fatalf("expected actionable malformed-rule error, got %q", err)
	}
}

// A malformed leaf must abort evaluation before a parent NOT can invert it.
func TestGraph_Validate_MalformedRequirementNestedInNOTFailsClosed(t *testing.T) {
	g := NewGraph()
	_ = g.AddRule("act-malformed-not", RequirementSet{
		ID:    "rs-root",
		Logic: AND,
		Children: []RequirementSet{{
			ID:           "rs-not",
			Logic:        NOT,
			Requirements: []Requirement{{ID: "r-malformed"}},
		}},
	})

	ok, hash, err := g.Validate("act-malformed-not", nil)
	if ok {
		t.Fatal("fail-open: malformed requirement was inverted by NOT")
	}
	if hash != "" {
		t.Fatalf("must not emit a rule hash for a malformed rule, got %q", hash)
	}
	if err == nil {
		t.Fatal("expected an error for a malformed requirement")
	}
	if !strings.Contains(err.Error(), "action act-malformed-not has malformed requirement") {
		t.Fatalf("expected actionable malformed-rule error, got %q", err)
	}
}
