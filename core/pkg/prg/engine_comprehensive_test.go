package prg

import (
	"strings"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
)

// --- NewPolicyEngine ---

func TestNewPolicyEngine_NotNil(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	if pe == nil {
		t.Fatal("nil")
	}
}

func TestNewPolicyEngine_CacheInitialized(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	if pe.prgCache == nil {
		t.Fatal("prgCache not initialized")
	}
}

func TestNewPolicyEngine_CacheEmpty(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	if len(pe.prgCache) != 0 {
		t.Fatalf("expected empty cache, got %d entries", len(pe.prgCache))
	}
}

func TestNewPolicyEngine_EnvNotNil(t *testing.T) {
	pe, err := NewPolicyEngine()
	if err != nil {
		t.Fatal(err)
	}
	if pe.env == nil {
		t.Fatal("CEL env is nil")
	}
}

// --- Evaluate: true / false ---

func TestEvaluate_TrueLiteral(t *testing.T) {
	pe, _ := NewPolicyEngine()
	result, err := pe.Evaluate("true", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true")
	}
}

func TestEvaluate_FalseLiteral(t *testing.T) {
	pe, _ := NewPolicyEngine()
	result, err := pe.Evaluate("false", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false")
	}
}

func TestEvaluate_OneEqualsOne(t *testing.T) {
	pe, _ := NewPolicyEngine()
	result, err := pe.Evaluate("1 == 1", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true")
	}
}

func TestEvaluate_OneEqualsTwo(t *testing.T) {
	pe, _ := NewPolicyEngine()
	result, err := pe.Evaluate("1 == 2", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false")
	}
}

func TestEvaluate_InputMapAccess_True(t *testing.T) {
	pe, _ := NewPolicyEngine()
	activation := map[string]interface{}{"input": map[string]interface{}{"x": 10}}
	result, err := pe.Evaluate(`input["x"] > 5`, activation)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true for x=10 > 5")
	}
}

func TestEvaluate_InputMapAccess_False(t *testing.T) {
	pe, _ := NewPolicyEngine()
	activation := map[string]interface{}{"input": map[string]interface{}{"x": 3}}
	result, err := pe.Evaluate(`input["x"] > 5`, activation)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false for x=3 > 5")
	}
}

func TestEvaluate_StringComparison(t *testing.T) {
	pe, _ := NewPolicyEngine()
	activation := map[string]interface{}{"input": map[string]interface{}{"role": "admin"}}
	result, err := pe.Evaluate(`input["role"] == "admin"`, activation)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true")
	}
}

func TestEvaluate_StringComparison_False(t *testing.T) {
	pe, _ := NewPolicyEngine()
	activation := map[string]interface{}{"input": map[string]interface{}{"role": "user"}}
	result, err := pe.Evaluate(`input["role"] == "admin"`, activation)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false")
	}
}

// --- Evaluate: errors ---

func TestEvaluate_CompileError_InvalidSyntax(t *testing.T) {
	pe, _ := NewPolicyEngine()
	_, err := pe.Evaluate(">>>invalid<<<", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "CEL compile error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvaluate_NonBoolResult(t *testing.T) {
	pe, _ := NewPolicyEngine()
	_, err := pe.Evaluate("42", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected non-bool error")
	}
	if !strings.Contains(err.Error(), "not boolean") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvaluate_NilInput(t *testing.T) {
	pe, _ := NewPolicyEngine()
	result, err := pe.Evaluate("true", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true even with nil input")
	}
}

// --- Evaluate: caching ---

func TestEvaluate_CachesCompiledProgram(t *testing.T) {
	pe, _ := NewPolicyEngine()
	_, _ = pe.Evaluate("true", map[string]interface{}{})
	pe.mu.RLock()
	_, cached := pe.prgCache["true"]
	pe.mu.RUnlock()
	if !cached {
		t.Fatal("expected expression to be cached")
	}
}

func TestEvaluate_CacheHitReturnsSameResult(t *testing.T) {
	pe, _ := NewPolicyEngine()
	r1, _ := pe.Evaluate("1 == 1", map[string]interface{}{})
	r2, _ := pe.Evaluate("1 == 1", map[string]interface{}{})
	if r1 != r2 {
		t.Fatal("cached and uncached results differ")
	}
}

// --- EvaluateRequirementSet: AND ---

func TestEvaluateRequirementSet_EmptySet_ReturnsTrue(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{ID: "empty"}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("empty set should return true")
	}
}

func TestEvaluateRequirementSet_AND_AllTrue(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", Expression: "true"},
			{ID: "r2", Expression: "true"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("AND of all true should be true")
	}
}

func TestEvaluateRequirementSet_AND_OneFalse(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: AND,
		Requirements: []Requirement{
			{ID: "r1", Expression: "true"},
			{ID: "r2", Expression: "false"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("AND with one false should be false")
	}
}

func TestEvaluateRequirementSet_DefaultLogic_IsAND(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{
			{ID: "r1", Expression: "true"},
			{ID: "r2", Expression: "false"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("default (AND) with one false should be false")
	}
}

// --- EvaluateRequirementSet: OR ---

func TestEvaluateRequirementSet_OR_OneTrue(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: OR,
		Requirements: []Requirement{
			{ID: "r1", Expression: "false"},
			{ID: "r2", Expression: "true"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("OR with one true should be true")
	}
}

func TestEvaluateRequirementSet_OR_AllFalse(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: OR,
		Requirements: []Requirement{
			{ID: "r1", Expression: "false"},
			{ID: "r2", Expression: "false"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("OR of all false should be false")
	}
}

// --- EvaluateRequirementSet: NOT ---

func TestEvaluateRequirementSet_NOT_InvertsTrue(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: NOT,
		Requirements: []Requirement{
			{ID: "r1", Expression: "true"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("NOT of true should be false")
	}
}

func TestEvaluateRequirementSet_NOT_InvertsFalse(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: NOT,
		Requirements: []Requirement{
			{ID: "r1", Expression: "false"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("NOT of false should be true")
	}
}

func TestEvaluateRequirementSet_NOT_AllTrue_ReturnsFalse(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: NOT,
		Requirements: []Requirement{
			{ID: "r1", Expression: "true"},
			{ID: "r2", Expression: "true"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("NOT of all-true should be false")
	}
}

func TestEvaluateRequirementSet_NOT_MixedResults(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: NOT,
		Requirements: []Requirement{
			{ID: "r1", Expression: "true"},
			{ID: "r2", Expression: "false"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("NOT with mixed (not all true) should be true")
	}
}

// --- EvaluateRequirementSet: nested children ---

func TestEvaluateRequirementSet_NestedChildren(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: OR,
		Children: []RequirementSet{
			{Logic: AND, Requirements: []Requirement{
				{ID: "c1r1", Expression: "false"},
			}},
			{Logic: AND, Requirements: []Requirement{
				{ID: "c2r1", Expression: "true"},
			}},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("OR(false child, true child) should be true")
	}
}

func TestEvaluateRequirementSet_NestedAND_AllChildrenTrue(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: AND,
		Children: []RequirementSet{
			{Requirements: []Requirement{{ID: "a", Expression: "true"}}},
			{Requirements: []Requirement{{ID: "b", Expression: "true"}}},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("AND of true children should be true")
	}
}

func TestEvaluateRequirementSet_NestedAND_OneChildFalse(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Logic: AND,
		Children: []RequirementSet{
			{Requirements: []Requirement{{ID: "a", Expression: "true"}}},
			{Requirements: []Requirement{{ID: "b", Expression: "false"}}},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("AND with one false child should be false")
	}
}

// --- EvaluateRequirementSet: requirement with no expression or artifact ---

func TestEvaluateRequirementSet_EmptyRequirement_Passes(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{{ID: "open"}},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("requirement with no expression or artifact should pass")
	}
}

// --- EvaluateRequirementSet: CEL with input ---

func TestEvaluateRequirementSet_CELWithInput(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{
			{ID: "r1", Expression: `input["level"] > 3`},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{"level": 5})
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true for level=5 > 3")
	}
}

// --- EvaluateRequirementSet: compile error propagation ---

func TestEvaluateRequirementSet_CompileError(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{
			{ID: "bad", Expression: "!!!"},
		},
	}
	_, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected compile error")
	}
}

// --- EvaluateRequirementSet: artifact type legacy ---

func TestEvaluateRequirementSet_ArtifactType_Found(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{
			{ID: "r1", ArtifactType: "evidence/alert"},
		},
	}
	input := map[string]interface{}{
		"artifacts": []*pkg_artifact.ArtifactEnvelope{
			{Type: "evidence/alert"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, input)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true when artifact type is found")
	}
}

func TestEvaluateRequirementSet_ArtifactType_NotFound(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{
			{ID: "r1", ArtifactType: "evidence/alert"},
		},
	}
	input := map[string]interface{}{
		"artifacts": []*pkg_artifact.ArtifactEnvelope{
			{Type: "evidence/other"},
		},
	}
	result, err := pe.EvaluateRequirementSet(rs, input)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false when artifact type is missing")
	}
}

func TestEvaluateRequirementSet_ArtifactType_WrongType(t *testing.T) {
	pe, _ := NewPolicyEngine()
	rs := RequirementSet{
		Requirements: []Requirement{
			{ID: "r1", ArtifactType: "evidence/alert"},
		},
	}
	input := map[string]interface{}{
		"artifacts": "not-a-slice",
	}
	result, err := pe.EvaluateRequirementSet(rs, input)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false when artifacts is wrong type")
	}
}

// --- combineResults ---

func TestCombineResults_UnknownLogic_ReturnsError(t *testing.T) {
	_, err := combineResults(LogicOperator("XOR"), []bool{true})
	if err == nil {
		t.Fatal("expected error for unknown logic")
	}
	if !strings.Contains(err.Error(), "unknown logic operator") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCombineResults_OR_Empty(t *testing.T) {
	result, err := combineResults(OR, []bool{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("OR of empty should be false")
	}
}

func TestCombineResults_NOT_Empty(t *testing.T) {
	result, err := combineResults(NOT, []bool{})
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("NOT of empty is !allTrue where allTrue=true vacuously, so result should be false")
	}
}

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

// --- RequirementSet.Hash ---

func TestRequirementSet_Hash_NotEmpty(t *testing.T) {
	rs := RequirementSet{ID: "rs-1", Logic: AND}
	h := rs.Hash()
	if h == "" {
		t.Fatal("expected non-empty hash")
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

