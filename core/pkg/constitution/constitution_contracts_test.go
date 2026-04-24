package constitution

import (
	"encoding/json"
	"testing"
)

func TestFinal_ConstitutionJSONRoundTrip(t *testing.T) {
	c := Constitution{ConstitutionID: "c1", AgentID: "a1", Version: "1.0.0"}
	data, _ := json.Marshal(c)
	var got Constitution
	json.Unmarshal(data, &got)
	if got.ConstitutionID != "c1" || got.AgentID != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PrincipleJSONRoundTrip(t *testing.T) {
	p := Principle{ID: "p1", Name: "Be safe", Priority: 1, Category: "safety"}
	data, _ := json.Marshal(p)
	var got Principle
	json.Unmarshal(data, &got)
	if got.ID != "p1" || got.Priority != 1 {
		t.Fatal("principle round-trip")
	}
}

func TestFinal_AlignmentScoreJSONRoundTrip(t *testing.T) {
	as := AlignmentScore{OverallScore: 0.85, PrincipleScores: map[string]float64{"p1": 1.0}}
	data, _ := json.Marshal(as)
	var got AlignmentScore
	json.Unmarshal(data, &got)
	if got.OverallScore != 0.85 {
		t.Fatal("alignment round-trip")
	}
}

func TestFinal_ValidCategories(t *testing.T) {
	expected := []string{"safety", "privacy", "helpfulness", "honesty", "fairness"}
	for _, cat := range expected {
		if !ValidCategories[cat] {
			t.Fatalf("missing category: %s", cat)
		}
	}
}

func TestFinal_PolicyConstraintJSONRoundTrip(t *testing.T) {
	pc := PolicyConstraint{PrincipleID: "p1", Expression: "true", Action: "deny", Priority: 1}
	data, _ := json.Marshal(pc)
	var got PolicyConstraint
	json.Unmarshal(data, &got)
	if got.Action != "deny" {
		t.Fatal("constraint round-trip")
	}
}

func TestFinal_NewAligner(t *testing.T) {
	a := NewAligner()
	if a == nil {
		t.Fatal("nil aligner")
	}
}

func TestFinal_AlignNilConstitution(t *testing.T) {
	a := NewAligner()
	constraints, err := a.Align(nil)
	if err != nil || constraints != nil {
		t.Fatal("nil constitution should return nil")
	}
}

func TestFinal_AlignSafetyPrinciple(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{{ID: "p1", Name: "Safety", Category: "safety", Priority: 1}}}
	constraints, _ := a.Align(c)
	if len(constraints) == 0 {
		t.Fatal("should produce constraints")
	}
}

func TestFinal_AlignCustomConstraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{{ID: "p1", Name: "Custom", Priority: 1, Constraints: []string{"input.ok == true"}}}}
	constraints, _ := a.Align(c)
	if len(constraints) != 1 || constraints[0].Expression != "input.ok == true" {
		t.Fatal("custom constraint not applied")
	}
}

func TestFinal_AlignUnknownCategory(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{{ID: "p1", Name: "Unknown", Category: "alien", Priority: 1}}}
	constraints, _ := a.Align(c)
	if len(constraints) == 0 {
		t.Fatal("unknown category should produce deny constraint")
	}
	if constraints[0].Action != "deny" {
		t.Fatal("unknown should deny")
	}
}

func TestFinal_AlignSorted(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "p2", Name: "Help", Category: "helpfulness", Priority: 2},
		{ID: "p1", Name: "Safety", Category: "safety", Priority: 1},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) < 2 {
		t.Fatal("should have multiple constraints")
	}
	for i := 1; i < len(constraints); i++ {
		if constraints[i].Priority < constraints[i-1].Priority {
			t.Fatal("not sorted by priority")
		}
	}
}

func TestFinal_ScoreNilConstitution(t *testing.T) {
	a := NewAligner()
	score := a.Score(nil, "act", "res", "ALLOW")
	if score.OverallScore != 0 {
		t.Fatal("nil should score 0")
	}
}

func TestFinal_ScoreSafetyDeny(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{{ID: "p1", Category: "safety", Priority: 1}}}
	score := a.Score(c, "delete", "production", "DENY")
	if score.PrincipleScores["p1"] != 1.0 {
		t.Fatal("safety deny risky should score 1.0")
	}
}

func TestFinal_ScoreHelpfulnessAllow(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{{ID: "p1", Category: "helpfulness", Priority: 1}}}
	score := a.Score(c, "read", "docs", "ALLOW")
	if score.PrincipleScores["p1"] != 1.0 {
		t.Fatal("helpfulness allow safe should score 1.0")
	}
}

func TestFinal_ScoreConflicts(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{{ID: "p1", Category: "safety", Priority: 1}}}
	score := a.Score(c, "delete", "production", "ALLOW")
	if len(score.Conflicts) == 0 {
		t.Fatal("should detect conflict")
	}
}

func TestFinal_InferCategoryPrivacy(t *testing.T) {
	cat := inferCategory("Protect user privacy at all costs")
	if cat != "privacy" {
		t.Fatalf("expected privacy, got %s", cat)
	}
}

func TestFinal_InferCategorySafety(t *testing.T) {
	cat := inferCategory("Ensure safety of all operations")
	if cat != "safety" {
		t.Fatalf("expected safety, got %s", cat)
	}
}

func TestFinal_InferCategoryHonesty(t *testing.T) {
	cat := inferCategory("Always be honest and truthful")
	if cat != "honesty" {
		t.Fatalf("expected honesty, got %s", cat)
	}
}

func TestFinal_InferCategoryDefault(t *testing.T) {
	cat := inferCategory("some random text")
	if cat != "safety" {
		t.Fatal("default should be safety")
	}
}

func TestFinal_TruncateNameShort(t *testing.T) {
	s := truncateName("hello", 64)
	if s != "hello" {
		t.Fatal("short string should not change")
	}
}

func TestFinal_TruncateNameLong(t *testing.T) {
	s := truncateName("this is a very long principle name that exceeds sixty-four characters easily", 64)
	if len(s) > 64 {
		t.Fatal("should be truncated")
	}
}

func TestFinal_NewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("nil parser")
	}
}

func TestFinal_ParseJSONValid(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","version":"1.0.0","principles":[{"id":"p1","name":"Be safe","priority":1,"category":"safety"}]}`
	c, err := p.ParseJSON([]byte(data))
	if err != nil || c.ConstitutionID != "c1" {
		t.Fatal("parse failed")
	}
}

func TestFinal_ParseJSONMissingID(t *testing.T) {
	p := NewParser()
	data := `{"agent_id":"a1","principles":[{"id":"p1","name":"Be safe","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("should error on missing ID")
	}
}

func TestFinal_ParseJSONDuplicatePriority(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[{"id":"p1","name":"A","priority":1},{"id":"p2","name":"B","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("should error on duplicate priority")
	}
}

func TestFinal_ParseJSONContentHashSet(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","version":"1.0.0","principles":[{"id":"p1","name":"Be safe","priority":1}]}`
	c, _ := p.ParseJSON([]byte(data))
	if c.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFinal_ParsePrinciplesValid(t *testing.T) {
	p := NewParser()
	text := "1. Be safe and secure\n2. Be helpful to users"
	c, err := p.ParsePrinciples("agent-1", text)
	if err != nil || len(c.Principles) != 2 {
		t.Fatal("parse principles failed")
	}
}

func TestFinal_ParsePrinciplesEmptyAgent(t *testing.T) {
	p := NewParser()
	_, err := p.ParsePrinciples("", "1. Be safe")
	if err == nil {
		t.Fatal("should error on empty agent")
	}
}

func TestFinal_ParsePrinciplesEmpty(t *testing.T) {
	p := NewParser()
	_, err := p.ParsePrinciples("a1", "")
	if err == nil {
		t.Fatal("should error on empty text")
	}
}

func TestFinal_InferActionDeny(t *testing.T) {
	action := inferAction("input.x != true")
	if action != "deny" {
		t.Fatalf("expected deny, got %s", action)
	}
}

func TestFinal_InferActionApproval(t *testing.T) {
	action := inferAction("requires_approval")
	if action != "require_approval" {
		t.Fatalf("expected require_approval, got %s", action)
	}
}

func TestFinal_InferActionAudit(t *testing.T) {
	action := inferAction("log everything")
	if action != "audit" {
		t.Fatalf("expected audit, got %s", action)
	}
}

func TestFinal_AlignmentConflictJSONRoundTrip(t *testing.T) {
	ac := AlignmentConflict{PrincipleID: "p1", Action: "delete", Reason: "risky"}
	data, _ := json.Marshal(ac)
	var got AlignmentConflict
	json.Unmarshal(data, &got)
	if got.PrincipleID != "p1" {
		t.Fatal("conflict round-trip")
	}
}

func TestFinal_IsRiskyActionTrue(t *testing.T) {
	if !isRiskyAction("delete", "records") {
		t.Fatal("delete should be risky")
	}
}

func TestFinal_IsRiskyActionResource(t *testing.T) {
	if !isRiskyAction("read", "production-database") {
		t.Fatal("production resource should be risky")
	}
}

func TestFinal_IsRiskyActionSafe(t *testing.T) {
	if isRiskyAction("read", "docs") {
		t.Fatal("read docs should not be risky")
	}
}

func TestFinal_IsDataAction(t *testing.T) {
	if !isDataAction("export-csv") {
		t.Fatal("export should be data action")
	}
}

func TestFinal_IsNotDataAction(t *testing.T) {
	if isDataAction("deploy") {
		t.Fatal("deploy is not data action")
	}
}
