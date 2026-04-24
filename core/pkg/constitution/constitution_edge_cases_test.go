package constitution

import (
	"encoding/json"
	"fmt"
	"testing"
)

func deepConstitution(n int) *Constitution {
	var principles []Principle
	for i := 1; i <= n; i++ {
		principles = append(principles, Principle{
			ID:       fmt.Sprintf("dp-%d", i),
			Name:     fmt.Sprintf("Deep Principle %d", i),
			Priority: i,
			Category: "safety",
		})
	}
	return &Constitution{
		ConstitutionID: "deep-const",
		AgentID:        "deep-agent-1",
		Version:        "1.0.0",
		Principles:     principles,
	}
}

func TestDeepParser20PrinciplesFromJSON(t *testing.T) {
	c := deepConstitution(20)
	data, _ := json.Marshal(c)
	p := NewParser()
	parsed, err := p.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Principles) != 20 {
		t.Fatalf("expected 20 principles, got %d", len(parsed.Principles))
	}
	if parsed.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestDeepParserRejectsDuplicatePriority(t *testing.T) {
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{
			{ID: "dp1", Name: "A", Priority: 1},
			{ID: "dp2", Name: "B", Priority: 1},
		},
	}
	data, _ := json.Marshal(c)
	_, err := NewParser().ParseJSON(data)
	if err == nil {
		t.Fatal("expected duplicate priority error")
	}
}

func TestDeepParserRejectsMissingConstitutionID(t *testing.T) {
	c := &Constitution{AgentID: "da1", Principles: []Principle{{ID: "dp1", Name: "N", Priority: 1}}}
	data, _ := json.Marshal(c)
	_, err := NewParser().ParseJSON(data)
	if err == nil {
		t.Fatal("should reject missing constitution_id")
	}
}

func TestDeepParserRejectsMissingAgentID(t *testing.T) {
	c := &Constitution{ConstitutionID: "dc1", Principles: []Principle{{ID: "dp1", Name: "N", Priority: 1}}}
	data, _ := json.Marshal(c)
	_, err := NewParser().ParseJSON(data)
	if err == nil {
		t.Fatal("should reject missing agent_id")
	}
}

func TestDeepParserRejectsNoPrinciples(t *testing.T) {
	c := &Constitution{ConstitutionID: "dc1", AgentID: "da1"}
	data, _ := json.Marshal(c)
	_, err := NewParser().ParseJSON(data)
	if err == nil {
		t.Fatal("should reject empty principles")
	}
}

func TestDeepParserRejectsZeroPriority(t *testing.T) {
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dp1", Name: "N", Priority: 0}},
	}
	data, _ := json.Marshal(c)
	_, err := NewParser().ParseJSON(data)
	if err == nil {
		t.Fatal("should reject priority < 1")
	}
}

func TestDeepParsePrinciplesText(t *testing.T) {
	text := "1. Be safe\n2. Be helpful\n3. Be honest"
	p := NewParser()
	c, err := p.ParsePrinciples("deep-agent", text)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Principles) != 3 {
		t.Fatalf("expected 3 principles, got %d", len(c.Principles))
	}
}

func TestDeepParsePrinciplesSkipsBlankLines(t *testing.T) {
	text := "1. Safety first\n\n\n2. Be fair"
	c, _ := NewParser().ParsePrinciples("da", text)
	if len(c.Principles) != 2 {
		t.Fatalf("expected 2 principles, got %d", len(c.Principles))
	}
}

func TestDeepAlignerConflictingSafetyVsHelpfulness(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{
			{ID: "dsafety", Name: "Safety", Priority: 1, Category: "safety"},
			{ID: "dhelpful", Name: "Helpfulness", Priority: 2, Category: "helpfulness"},
		},
	}
	score := aligner.Score(c, "read_file", "local", "DENY")
	if score.OverallScore >= 1.0 {
		t.Fatal("DENY on safe action should not score perfectly")
	}
	if len(score.Conflicts) == 0 {
		t.Fatal("should detect helpfulness conflict")
	}
}

func TestDeepAlignerScoreAllowRiskyAction(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dsafety", Name: "Safety", Priority: 1, Category: "safety"}},
	}
	score := aligner.Score(c, "delete_production", "database", "ALLOW")
	if score.PrincipleScores["dsafety"] != 0.0 {
		t.Fatalf("ALLOW risky action: safety score should be 0.0, got %f", score.PrincipleScores["dsafety"])
	}
}

func TestDeepAlignerScoreDenyRiskyAction(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dsafety", Name: "Safety", Priority: 1, Category: "safety"}},
	}
	score := aligner.Score(c, "execute_script", "production", "DENY")
	if score.PrincipleScores["dsafety"] != 1.0 {
		t.Fatalf("DENY risky: safety should be 1.0, got %f", score.PrincipleScores["dsafety"])
	}
}

func TestDeepAlignerScoreEscalateVerdict(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dsafety", Name: "Safety", Priority: 1, Category: "safety"}},
	}
	score := aligner.Score(c, "deploy", "staging", "ESCALATE")
	if score.OverallScore == 0.0 || score.OverallScore == 1.0 {
		t.Fatalf("ESCALATE should produce neutral score, got %f", score.OverallScore)
	}
}

func TestDeepAlignerCustomCELConstraints(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{
			ID: "dcustom", Name: "Custom Rule", Priority: 1,
			Constraints: []string{`input.risk != "critical"`, `input.approved == true`},
		}},
	}
	constraints, err := aligner.Align(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 2 {
		t.Fatalf("expected 2 constraints, got %d", len(constraints))
	}
	if constraints[0].PrincipleID != "dcustom" {
		t.Fatal("constraint should reference the principle ID")
	}
}

func TestDeepAlignerCategoryFallbackRules(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dp1", Name: "Privacy", Priority: 1, Category: "privacy"}},
	}
	constraints, _ := aligner.Align(c)
	if len(constraints) == 0 {
		t.Fatal("privacy category should have default rules")
	}
}

func TestDeepAlignerUnknownCategoryDeny(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dp1", Name: "Alien", Priority: 1, Category: "alien_category"}},
	}
	constraints, _ := aligner.Align(c)
	if len(constraints) != 1 || constraints[0].Action != "deny" {
		t.Fatal("unknown category should produce a deny rule (fail-closed)")
	}
}

func TestDeepAlignerNilConstitution(t *testing.T) {
	aligner := NewAligner()
	constraints, _ := aligner.Align(nil)
	if constraints != nil {
		t.Fatal("nil constitution should return nil constraints")
	}
}

func TestDeepInferCategorySafety(t *testing.T) {
	if inferCategory("Protect users from harm") != "safety" {
		t.Fatal("should infer safety")
	}
}

func TestDeepInferCategoryPrivacy(t *testing.T) {
	if inferCategory("Protect user privacy at all times") != "privacy" {
		t.Fatal("should infer privacy")
	}
}

func TestDeepInferCategoryHonesty(t *testing.T) {
	if inferCategory("Always be truthful and transparent") != "honesty" {
		t.Fatal("should infer honesty")
	}
}

func TestDeepInferCategoryFairness(t *testing.T) {
	if inferCategory("Avoid bias and discrimination") != "fairness" {
		t.Fatal("should infer fairness")
	}
}

func TestDeepInferCategoryHelpfulness(t *testing.T) {
	if inferCategory("Be as helpful and useful as possible") != "helpfulness" {
		t.Fatal("should infer helpfulness")
	}
}

func TestDeepInferCategoryDefaultSafety(t *testing.T) {
	if inferCategory("Some completely unrelated principle about quantum mechanics") != "safety" {
		t.Fatal("unknown text should default to safety")
	}
}

func TestDeepAlignerConstraintsSortedByPriority(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{
			{ID: "dp3", Name: "Low", Priority: 3, Category: "safety"},
			{ID: "dp1", Name: "High", Priority: 1, Category: "privacy"},
		},
	}
	constraints, _ := aligner.Align(c)
	for i := 1; i < len(constraints); i++ {
		if constraints[i].Priority < constraints[i-1].Priority {
			t.Fatal("constraints should be sorted by priority ascending")
		}
	}
}

func TestDeepAlignerScorePrivacyDenyDataAction(t *testing.T) {
	aligner := NewAligner()
	c := &Constitution{
		ConstitutionID: "dc1", AgentID: "da1",
		Principles: []Principle{{ID: "dpriv", Name: "Privacy", Priority: 1, Category: "privacy"}},
	}
	score := aligner.Score(c, "export_data", "user_db", "DENY")
	if score.PrincipleScores["dpriv"] != 1.0 {
		t.Fatalf("DENY data export: privacy should be 1.0, got %f", score.PrincipleScores["dpriv"])
	}
}

func TestDeepAlignerScoreNilConstitution(t *testing.T) {
	aligner := NewAligner()
	score := aligner.Score(nil, "anything", "anywhere", "ALLOW")
	if score.OverallScore != 0 {
		t.Fatal("nil constitution should score 0")
	}
}
