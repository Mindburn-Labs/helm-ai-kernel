package constitution

import (
	"encoding/json"
	"fmt"
	"testing"
)

// --- Parser Stress ---

func TestStress_Parser_50Principles(t *testing.T) {
	var text string
	for i := 1; i <= 50; i++ {
		text += fmt.Sprintf("%d. Principle about safety and fairness number %d\n", i, i)
	}
	p := NewParser()
	c, err := p.ParsePrinciples("agent-50", text)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Principles) != 50 {
		t.Fatalf("expected 50 principles, got %d", len(c.Principles))
	}
}

func TestStress_Parser_EmptyTextRejected(t *testing.T) {
	p := NewParser()
	_, err := p.ParsePrinciples("agent-1", "")
	if err == nil {
		t.Fatal("expected error for empty text")
	}
}

func TestStress_Parser_EmptyAgentIDRejected(t *testing.T) {
	p := NewParser()
	_, err := p.ParsePrinciples("", "1. Be safe")
	if err == nil {
		t.Fatal("expected error for empty agentID")
	}
}

func TestStress_Parser_JSONMissingConstitutionID(t *testing.T) {
	p := NewParser()
	data := `{"agent_id":"a","principles":[{"id":"p1","name":"n","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing constitution_id")
	}
}

func TestStress_Parser_JSONMissingAgentID(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","principles":[{"id":"p1","name":"n","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing agent_id")
	}
}

func TestStress_Parser_JSONNoPrinciples(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for empty principles")
	}
}

func TestStress_Parser_JSONDuplicatePriority(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[{"id":"p1","name":"n1","priority":1},{"id":"p2","name":"n2","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for duplicate priority")
	}
}

func TestStress_Parser_JSONInvalidPriority(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[{"id":"p1","name":"n1","priority":0}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for priority < 1")
	}
}

func TestStress_Parser_JSONMissingPrincipleID(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[{"name":"n1","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing principle id")
	}
}

func TestStress_Parser_JSONMissingPrincipleName(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[{"id":"p1","priority":1}]}`
	_, err := p.ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing principle name")
	}
}

// --- Aligner Stress: 5 categories x 3 constraints ---

func TestStress_Aligner_Safety3Constraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "s1", Name: "Safe1", Priority: 1, Category: "safety"},
		{ID: "s2", Name: "Safe2", Priority: 2, Category: "safety"},
		{ID: "s3", Name: "Safe3", Priority: 3, Category: "safety"},
	}}
	constraints, err := a.Align(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) < 3 {
		t.Fatalf("expected at least 3 constraints, got %d", len(constraints))
	}
}

func TestStress_Aligner_Privacy3Constraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "p1", Name: "Priv1", Priority: 1, Category: "privacy"},
		{ID: "p2", Name: "Priv2", Priority: 2, Category: "privacy"},
		{ID: "p3", Name: "Priv3", Priority: 3, Category: "privacy"},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) < 3 {
		t.Fatalf("expected at least 3 constraints, got %d", len(constraints))
	}
}

func TestStress_Aligner_Helpfulness3Constraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "h1", Name: "Help1", Priority: 1, Category: "helpfulness"},
		{ID: "h2", Name: "Help2", Priority: 2, Category: "helpfulness"},
		{ID: "h3", Name: "Help3", Priority: 3, Category: "helpfulness"},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) < 3 {
		t.Fatalf("expected at least 3 constraints, got %d", len(constraints))
	}
}

func TestStress_Aligner_Honesty3Constraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "o1", Name: "Hon1", Priority: 1, Category: "honesty"},
		{ID: "o2", Name: "Hon2", Priority: 2, Category: "honesty"},
		{ID: "o3", Name: "Hon3", Priority: 3, Category: "honesty"},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) < 3 {
		t.Fatalf("expected at least 3 constraints, got %d", len(constraints))
	}
}

func TestStress_Aligner_Fairness3Constraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "f1", Name: "Fair1", Priority: 1, Category: "fairness"},
		{ID: "f2", Name: "Fair2", Priority: 2, Category: "fairness"},
		{ID: "f3", Name: "Fair3", Priority: 3, Category: "fairness"},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) < 3 {
		t.Fatalf("expected at least 3 constraints, got %d", len(constraints))
	}
}

func TestStress_Aligner_UnknownCategoryFallback(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "u1", Name: "Unknown", Priority: 1, Category: "unknown_cat"},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) == 0 {
		t.Fatal("expected fallback constraint for unknown category")
	}
	if constraints[0].Action != "deny" {
		t.Fatalf("unknown category should default to deny, got %s", constraints[0].Action)
	}
}

func TestStress_Aligner_CustomConstraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "c1", Name: "Custom", Priority: 1, Category: "safety",
			Constraints: []string{"input.admin == false", "input.risk != 'critical'"}},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) != 2 {
		t.Fatalf("expected 2 custom constraints, got %d", len(constraints))
	}
}

func TestStress_Aligner_NilConstitution(t *testing.T) {
	a := NewAligner()
	constraints, err := a.Align(nil)
	if err != nil {
		t.Fatal(err)
	}
	if constraints != nil {
		t.Fatal("expected nil constraints for nil constitution")
	}
}

func TestStress_Aligner_PrioritySorted(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "p3", Name: "Third", Priority: 3, Category: "safety"},
		{ID: "p1", Name: "First", Priority: 1, Category: "safety"},
	}}
	constraints, _ := a.Align(c)
	for i := 1; i < len(constraints); i++ {
		if constraints[i].Priority < constraints[i-1].Priority {
			t.Fatal("constraints not sorted by priority")
		}
	}
}

// --- Score Stress: verdict x category combinations ---

func TestStress_Score_SafetyDenyRisky(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "s1", Name: "Safety", Priority: 1, Category: "safety"},
	}}
	score := a.Score(c, "delete", "production", "DENY")
	if score.PrincipleScores["s1"] != 1.0 {
		t.Fatalf("safety+deny+risky should be 1.0, got %f", score.PrincipleScores["s1"])
	}
}

func TestStress_Score_SafetyAllowRisky(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "s1", Name: "Safety", Priority: 1, Category: "safety"},
	}}
	score := a.Score(c, "delete", "production", "ALLOW")
	if score.PrincipleScores["s1"] != 0.0 {
		t.Fatalf("safety+allow+risky should be 0.0, got %f", score.PrincipleScores["s1"])
	}
}

func TestStress_Score_SafetyAllowSafe(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "s1", Name: "Safety", Priority: 1, Category: "safety"},
	}}
	score := a.Score(c, "read", "docs", "ALLOW")
	if score.PrincipleScores["s1"] != 0.8 {
		t.Fatalf("safety+allow+safe should be 0.8, got %f", score.PrincipleScores["s1"])
	}
}

func TestStress_Score_PrivacyDenyData(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "p1", Name: "Privacy", Priority: 1, Category: "privacy"},
	}}
	score := a.Score(c, "export", "data", "DENY")
	if score.PrincipleScores["p1"] != 1.0 {
		t.Fatalf("privacy+deny+data should be 1.0, got %f", score.PrincipleScores["p1"])
	}
}

func TestStress_Score_PrivacyAllowData(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "p1", Name: "Privacy", Priority: 1, Category: "privacy"},
	}}
	score := a.Score(c, "export", "data", "ALLOW")
	if score.PrincipleScores["p1"] != 0.3 {
		t.Fatalf("privacy+allow+data should be 0.3, got %f", score.PrincipleScores["p1"])
	}
}

func TestStress_Score_HelpfulnessAllowSafe(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "h1", Name: "Help", Priority: 1, Category: "helpfulness"},
	}}
	score := a.Score(c, "read", "docs", "ALLOW")
	if score.PrincipleScores["h1"] != 1.0 {
		t.Fatalf("helpfulness+allow+safe should be 1.0, got %f", score.PrincipleScores["h1"])
	}
}

func TestStress_Score_HelpfulnessDenySafe(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "h1", Name: "Help", Priority: 1, Category: "helpfulness"},
	}}
	score := a.Score(c, "read", "docs", "DENY")
	if score.PrincipleScores["h1"] != 0.2 {
		t.Fatalf("helpfulness+deny+safe should be 0.2, got %f", score.PrincipleScores["h1"])
	}
}

func TestStress_Score_HonestyAlways07(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "o1", Name: "Honesty", Priority: 1, Category: "honesty"},
	}}
	score := a.Score(c, "anything", "anything", "ALLOW")
	if score.PrincipleScores["o1"] != 0.7 {
		t.Fatalf("honesty should always be 0.7, got %f", score.PrincipleScores["o1"])
	}
}

func TestStress_Score_FairnessDenyDiscriminatory(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "f1", Name: "Fairness", Priority: 1, Category: "fairness"},
	}}
	score := a.Score(c, "discriminate_action", "users", "DENY")
	if score.PrincipleScores["f1"] != 1.0 {
		t.Fatalf("fairness+deny+discriminatory should be 1.0, got %f", score.PrincipleScores["f1"])
	}
}

func TestStress_Score_FairnessAllowDiscriminatory(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "f1", Name: "Fairness", Priority: 1, Category: "fairness"},
	}}
	score := a.Score(c, "discriminate_action", "users", "ALLOW")
	if score.PrincipleScores["f1"] != 0.0 {
		t.Fatalf("fairness+allow+discriminatory should be 0.0, got %f", score.PrincipleScores["f1"])
	}
}

func TestStress_Score_EmptyConstitution(t *testing.T) {
	a := NewAligner()
	score := a.Score(nil, "read", "docs", "ALLOW")
	if score.OverallScore != 0 {
		t.Fatalf("nil constitution should have score 0, got %f", score.OverallScore)
	}
}

// --- JSON / Content Hash Stress ---

func TestStress_JSON_DeeplyNested(t *testing.T) {
	principles := make([]Principle, 20)
	for i := range principles {
		constraints := make([]string, 5)
		for j := range constraints {
			constraints[j] = fmt.Sprintf("input.nested.field_%d_%d != true", i, j)
		}
		principles[i] = Principle{
			ID: fmt.Sprintf("p-%d", i+1), Name: fmt.Sprintf("Principle %d", i+1),
			Priority: i + 1, Category: "safety", Constraints: constraints,
		}
	}
	c := Constitution{
		ConstitutionID: "deep-nest", AgentID: "agent-deep",
		Version: "1.0.0", Principles: principles,
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p := NewParser()
	parsed, err := p.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Principles) != 20 {
		t.Fatalf("expected 20 principles, got %d", len(parsed.Principles))
	}
}

func TestStress_ContentHash_Determinism100(t *testing.T) {
	p := NewParser()
	data := `{"constitution_id":"det","agent_id":"a","version":"1.0","principles":[{"id":"p1","name":"Safety first","priority":1,"category":"safety"}]}`
	first, err := p.ParseJSON([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		c, err := p.ParseJSON([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if c.ContentHash != first.ContentHash {
			t.Fatalf("content hash not deterministic at iteration %d", i)
		}
	}
}

func TestStress_InferCategory_Safety(t *testing.T) {
	cat := inferCategory("Protect users from dangerous actions")
	if cat != "safety" {
		t.Fatalf("expected safety, got %s", cat)
	}
}

func TestStress_InferCategory_Privacy(t *testing.T) {
	cat := inferCategory("Respect user privacy and confidential data")
	if cat != "privacy" {
		t.Fatalf("expected privacy, got %s", cat)
	}
}

func TestStress_InferCategory_Fairness(t *testing.T) {
	cat := inferCategory("Treat all users fairly without bias")
	if cat != "fairness" {
		t.Fatalf("expected fairness, got %s", cat)
	}
}

func TestStress_InferCategory_Honesty(t *testing.T) {
	cat := inferCategory("Always be honest and truthful")
	if cat != "honesty" {
		t.Fatalf("expected honesty, got %s", cat)
	}
}

func TestStress_InferCategory_Helpfulness(t *testing.T) {
	cat := inferCategory("Be helpful and assist users")
	if cat != "helpfulness" {
		t.Fatalf("expected helpfulness, got %s", cat)
	}
}

func TestStress_InferCategory_Default(t *testing.T) {
	cat := inferCategory("Do something random")
	if cat != "safety" {
		t.Fatalf("expected safety default, got %s", cat)
	}
}

func TestStress_TruncateName_Short(t *testing.T) {
	result := truncateName("short", 64)
	if result != "short" {
		t.Fatalf("expected unchanged, got %s", result)
	}
}

func TestStress_TruncateName_Long(t *testing.T) {
	long := "This is a very long principle name that exceeds the maximum allowed length for names"
	result := truncateName(long, 30)
	if len(result) > 30 {
		t.Fatalf("truncated name too long: %d", len(result))
	}
}
