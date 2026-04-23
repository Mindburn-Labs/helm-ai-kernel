package cpi

import (
	"encoding/json"
	"testing"
)

func TestValidateEmptyStack(t *testing.T) {
	result, err := Validate(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var vr ValidationResult
	if err := json.Unmarshal(result, &vr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if vr.Verdict != VerdictConsistent {
		t.Fatalf("expected CONSISTENT, got %s", vr.Verdict)
	}
}

func TestValidateConsistentStack(t *testing.T) {
	layers := []PolicyLayer{
		{
			Name:     "P0",
			Priority: 0,
			Rules: []PolicyRule{
				{ID: "max-budget", Action: "*", Verdict: "DENY", Reason: "budget ceiling"},
			},
		},
		{
			Name:     "P1",
			Priority: 1,
			Rules: []PolicyRule{
				{ID: "allow-read", Action: "read.*", Verdict: "ALLOW", Reason: "reads permitted"},
			},
		},
	}
	facts, _ := json.Marshal(layers)

	result, err := Validate(nil, nil, nil, facts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var vr ValidationResult
	if err := json.Unmarshal(result, &vr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// P0 denies "*" and P1 allows "read.*" — this is a widening conflict
	if vr.Verdict != VerdictConflict {
		t.Fatalf("expected CONFLICT (P1 widens P0 denial), got %s", vr.Verdict)
	}
	if len(vr.Conflicts) == 0 {
		t.Fatal("expected at least one conflict")
	}
}

func TestValidateNoConflictDifferentActions(t *testing.T) {
	layers := []PolicyLayer{
		{
			Name:     "P0",
			Priority: 0,
			Rules: []PolicyRule{
				{ID: "deny-delete", Action: "delete.*", Verdict: "DENY", Reason: "no deletes"},
			},
		},
		{
			Name:     "P1",
			Priority: 1,
			Rules: []PolicyRule{
				{ID: "allow-read", Action: "read.*", Verdict: "ALLOW", Reason: "reads ok"},
			},
		},
	}
	facts, _ := json.Marshal(layers)

	result, err := Validate(nil, nil, nil, facts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var vr ValidationResult
	if err := json.Unmarshal(result, &vr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if vr.Verdict != VerdictConsistent {
		t.Fatalf("expected CONSISTENT, got %s", vr.Verdict)
	}
}

func TestValidateInvalidJSON(t *testing.T) {
	_, err := Validate(nil, nil, nil, []byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCompileValid(t *testing.T) {
	layers := []PolicyLayer{
		{
			Name:     "P1",
			Priority: 1,
			Rules: []PolicyRule{
				{ID: "rule1", Action: "write.*", Verdict: "DENY", Reason: "no writes"},
			},
		},
	}
	source, _ := json.Marshal(layers)

	compiled, err := Compile(source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var bundle CompiledBundle
	if err := json.Unmarshal(compiled, &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if bundle.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(bundle.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(bundle.Layers))
	}
}

func TestCompileMissingName(t *testing.T) {
	layers := []PolicyLayer{
		{Priority: 0, Rules: []PolicyRule{{ID: "r1", Action: "*", Verdict: "DENY"}}},
	}
	source, _ := json.Marshal(layers)
	_, err := Compile(source)
	if err == nil {
		t.Fatal("expected error for missing layer name")
	}
}

func TestCompileInvalidVerdict(t *testing.T) {
	layers := []PolicyLayer{
		{Name: "P1", Priority: 0, Rules: []PolicyRule{{ID: "r1", Action: "*", Verdict: "MAYBE"}}},
	}
	source, _ := json.Marshal(layers)
	_, err := Compile(source)
	if err == nil {
		t.Fatal("expected error for invalid verdict")
	}
}

func TestExplainConsistent(t *testing.T) {
	result := &ValidationResult{
		Verdict: VerdictConsistent,
		Hash:    "abc",
		Layers: []LayerSummary{
			{Name: "P0", RuleCount: 2, Hash: "aabbccdd1122334455"},
		},
	}
	data, _ := json.Marshal(result)

	explained, err := Explain(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var exp Explanation
	if err := json.Unmarshal(explained, &exp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if exp.Verdict != VerdictConsistent {
		t.Fatalf("expected CONSISTENT, got %s", exp.Verdict)
	}
	if exp.Summary == "" {
		t.Fatal("expected non-empty summary")
	}
}

func TestExplainConflict(t *testing.T) {
	result := &ValidationResult{
		Verdict: VerdictConflict,
		Hash:    "abc",
		Conflicts: []Conflict{
			{LayerA: "P0", LayerB: "P1", RuleA: "r1", RuleB: "r2", Action: "*", Detail: "test"},
		},
		Layers: []LayerSummary{
			{Name: "P0", RuleCount: 1, Hash: "aabbccdd"},
			{Name: "P1", RuleCount: 1, Hash: "eeff0011"},
		},
	}
	data, _ := json.Marshal(result)

	explained, err := Explain(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var exp Explanation
	if err := json.Unmarshal(explained, &exp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if exp.Verdict != VerdictConflict {
		t.Fatalf("expected CONFLICT, got %s", exp.Verdict)
	}
	if len(exp.Details) == 0 {
		t.Fatal("expected conflict details")
	}
}

func TestExplainNilInput(t *testing.T) {
	_, err := Explain(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestActionsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"*", "read", true},
		{"read", "*", true},
		{"read", "read", true},
		{"read", "write", false},
		{"write.*", "write.file", true},
		{"write.*", "read.file", false},
		{"read.file", "write.*", false},
	}
	for _, tc := range cases {
		got := actionsOverlap(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("actionsOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompileEmpty(t *testing.T) {
	_, err := Compile(nil)
	if err == nil {
		t.Fatal("expected error for nil source")
	}
}

func TestValidateHashDeterminism(t *testing.T) {
	layers := []PolicyLayer{
		{Name: "P0", Priority: 0, Rules: []PolicyRule{
			{ID: "r1", Action: "*", Verdict: "DENY", Reason: "no"},
		}},
	}
	facts, _ := json.Marshal(layers)

	r1, _ := Validate(nil, nil, nil, facts)
	r2, _ := Validate(nil, nil, nil, facts)

	var vr1, vr2 ValidationResult
	json.Unmarshal(r1, &vr1)
	json.Unmarshal(r2, &vr2)

	if vr1.Hash != vr2.Hash {
		t.Fatalf("hash not deterministic: %q vs %q", vr1.Hash, vr2.Hash)
	}
}
