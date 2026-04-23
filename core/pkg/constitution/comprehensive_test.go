package constitution

import (
	"encoding/json"
	"testing"
)

// ── Parser: JSON ──

func TestParseJSON_Valid(t *testing.T) {
	c := Constitution{
		ConstitutionID: "c1", AgentID: "a1", Version: "1.0.0",
		Principles: []Principle{{ID: "p1", Name: "Be safe", Priority: 1, Category: "safety"}},
	}
	data, _ := json.Marshal(c)
	p := NewParser()
	got, err := p.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestParseJSON_MissingConstitutionID(t *testing.T) {
	data := `{"agent_id":"a1","principles":[{"id":"p1","name":"x","priority":1}]}`
	_, err := NewParser().ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing constitution_id")
	}
}

func TestParseJSON_MissingAgentID(t *testing.T) {
	data := `{"constitution_id":"c1","principles":[{"id":"p1","name":"x","priority":1}]}`
	_, err := NewParser().ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing agent_id")
	}
}

func TestParseJSON_NoPrinciples(t *testing.T) {
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[]}`
	_, err := NewParser().ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for empty principles")
	}
}

func TestParseJSON_DuplicatePriority(t *testing.T) {
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[
		{"id":"p1","name":"A","priority":1},
		{"id":"p2","name":"B","priority":1}
	]}`
	_, err := NewParser().ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for duplicate priority")
	}
}

func TestParseJSON_ZeroPriority(t *testing.T) {
	data := `{"constitution_id":"c1","agent_id":"a1","principles":[
		{"id":"p1","name":"A","priority":0}
	]}`
	_, err := NewParser().ParseJSON([]byte(data))
	if err == nil {
		t.Fatal("expected error for priority < 1")
	}
}

func TestParseJSON_InvalidJSON(t *testing.T) {
	_, err := NewParser().ParseJSON([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ── Parser: Principles Text ──

func TestParsePrinciples_Valid(t *testing.T) {
	text := "1. Be safe and protect users\n2. Be honest and transparent"
	c, err := NewParser().ParsePrinciples("agent-1", text)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Principles) != 2 {
		t.Fatalf("expected 2 principles, got %d", len(c.Principles))
	}
}

func TestParsePrinciples_EmptyAgent(t *testing.T) {
	_, err := NewParser().ParsePrinciples("", "1. Test")
	if err == nil {
		t.Fatal("expected error for empty agent_id")
	}
}

func TestParsePrinciples_NoValidLines(t *testing.T) {
	_, err := NewParser().ParsePrinciples("a1", "no numbered lines here")
	if err == nil {
		t.Fatal("expected error when no valid principles found")
	}
}

func TestParsePrinciples_CategoryInference(t *testing.T) {
	text := "1. Protect user privacy at all costs"
	c, _ := NewParser().ParsePrinciples("a1", text)
	if c.Principles[0].Category != "privacy" {
		t.Fatalf("expected privacy category, got %s", c.Principles[0].Category)
	}
}

// ── Aligner ──

func TestAligner_AlignNilConstitution(t *testing.T) {
	a := NewAligner()
	constraints, err := a.Align(nil)
	if err != nil || constraints != nil {
		t.Fatal("nil constitution should return nil, nil")
	}
}

func TestAligner_AlignSafetyCategory(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "p1", Name: "Safety", Priority: 1, Category: "safety"},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) != 2 {
		t.Fatalf("expected 2 safety constraints, got %d", len(constraints))
	}
}

func TestAligner_AlignCustomConstraints(t *testing.T) {
	a := NewAligner()
	c := &Constitution{Principles: []Principle{
		{ID: "p1", Name: "Custom", Priority: 1, Constraints: []string{`input.x != "bad"`}},
	}}
	constraints, _ := a.Align(c)
	if len(constraints) != 1 || constraints[0].Expression != `input.x != "bad"` {
		t.Fatal("expected custom constraint expression")
	}
}

func TestAligner_ScoreRiskyDeny(t *testing.T) {
	a := NewAligner()
	c := &Constitution{ConstitutionID: "c1", Principles: []Principle{
		{ID: "p1", Name: "Safety", Priority: 1, Category: "safety"},
	}}
	score := a.Score(c, "delete", "production", "DENY")
	if score.PrincipleScores["p1"] != 1.0 {
		t.Fatalf("expected perfect safety alignment, got %f", score.PrincipleScores["p1"])
	}
}
