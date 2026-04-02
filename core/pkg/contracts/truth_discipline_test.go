package contracts_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────
// TruthAnnotation tests
// ──────────────────────────────────────────────────────────────

func TestTruthAnnotation_HasBlockingUnknowns(t *testing.T) {
	ta := &contracts.TruthAnnotation{
		Unknowns: []contracts.Unknown{
			{ID: "u1", Impact: contracts.UnknownImpactInformational},
			{ID: "u2", Impact: contracts.UnknownImpactBlocking},
		},
	}
	if !ta.HasBlockingUnknowns() {
		t.Fatal("expected blocking unknowns")
	}

	ta2 := &contracts.TruthAnnotation{
		Unknowns: []contracts.Unknown{
			{ID: "u1", Impact: contracts.UnknownImpactDegrading},
		},
	}
	if ta2.HasBlockingUnknowns() {
		t.Fatal("expected no blocking unknowns")
	}
}

func TestTruthAnnotation_BlockingUnknownIDs(t *testing.T) {
	ta := &contracts.TruthAnnotation{
		Unknowns: []contracts.Unknown{
			{ID: "u1", Impact: contracts.UnknownImpactBlocking},
			{ID: "u2", Impact: contracts.UnknownImpactDegrading},
			{ID: "u3", Impact: contracts.UnknownImpactBlocking},
		},
	}
	ids := ta.BlockingUnknownIDs()
	if len(ids) != 2 || ids[0] != "u1" || ids[1] != "u3" {
		t.Fatalf("expected [u1, u3], got %v", ids)
	}
}

func TestTruthAnnotation_Merge(t *testing.T) {
	a := &contracts.TruthAnnotation{
		FactSet:    []contracts.FactRef{{FactID: "f1"}},
		Confidence: 0.8,
		Unknowns:   []contracts.Unknown{{ID: "u1"}},
	}
	b := &contracts.TruthAnnotation{
		FactSet:    []contracts.FactRef{{FactID: "f2"}},
		Confidence: 0.5,
		Unknowns:   []contracts.Unknown{{ID: "u2"}},
	}

	merged := a.Merge(b)
	if len(merged.FactSet) != 2 {
		t.Fatalf("expected 2 facts, got %d", len(merged.FactSet))
	}
	if len(merged.Unknowns) != 2 {
		t.Fatalf("expected 2 unknowns, got %d", len(merged.Unknowns))
	}
	if merged.Confidence != 0.5 {
		t.Fatalf("expected lower confidence 0.5, got %f", merged.Confidence)
	}
}

func TestTruthAnnotation_Merge_NilOther(t *testing.T) {
	a := &contracts.TruthAnnotation{Confidence: 0.9}
	merged := a.Merge(nil)
	if merged != a {
		t.Fatal("expected same pointer for nil merge")
	}
}

func TestTruthAnnotation_Merge_ZeroConfidence(t *testing.T) {
	a := &contracts.TruthAnnotation{Confidence: 0.7}
	b := &contracts.TruthAnnotation{Confidence: 0}
	merged := a.Merge(b)
	if merged.Confidence != 0.7 {
		t.Fatalf("expected 0.7 when other is zero, got %f", merged.Confidence)
	}
}

func TestTruthAnnotation_EmptyHasNoBlockingUnknowns(t *testing.T) {
	ta := &contracts.TruthAnnotation{}
	if ta.HasBlockingUnknowns() {
		t.Fatal("empty annotation should have no blocking unknowns")
	}
	if ids := ta.BlockingUnknownIDs(); len(ids) != 0 {
		t.Fatalf("expected empty, got %v", ids)
	}
}

// ──────────────────────────────────────────────────────────────
// JSON backward compatibility tests
// ──────────────────────────────────────────────────────────────

func TestPlanStep_BackwardCompat_OldJSON(t *testing.T) {
	// Old PlanStep JSON without truth discipline fields.
	oldJSON := `{
		"id": "step-1",
		"effect_type": "FS_WRITE",
		"description": "Write config file",
		"assumptions": ["Config dir exists"],
		"acceptance_criteria": ["File written"]
	}`

	var step contracts.PlanStep
	if err := json.Unmarshal([]byte(oldJSON), &step); err != nil {
		t.Fatalf("failed to unmarshal old PlanStep JSON: %v", err)
	}
	if step.ID != "step-1" {
		t.Fatalf("expected id step-1, got %s", step.ID)
	}
	if step.EffectType != "FS_WRITE" {
		t.Fatalf("expected effect_type FS_WRITE, got %s", step.EffectType)
	}
	if len(step.Assumptions) != 1 || step.Assumptions[0] != "Config dir exists" {
		t.Fatalf("assumptions mismatch: %v", step.Assumptions)
	}
	// New fields should be zero-valued.
	if step.Justification != "" {
		t.Fatalf("expected empty justification, got %s", step.Justification)
	}
	if step.Confidence != 0 {
		t.Fatalf("expected zero confidence, got %f", step.Confidence)
	}
	if step.RequestedBackend != "" {
		t.Fatalf("expected empty backend, got %s", step.RequestedBackend)
	}
	if len(step.FactSet) != 0 {
		t.Fatalf("expected empty fact_set, got %v", step.FactSet)
	}
}

func TestPlanStep_NewJSON_Roundtrip(t *testing.T) {
	step := contracts.PlanStep{
		ID:          "step-1",
		EffectType:  "NETWORK",
		Description: "Call external API",
		Assumptions: []string{"API is up"},
		AcceptanceCriteria: []string{"200 OK"},
		Justification:     "Required for data sync",
		FactSet: []contracts.FactRef{
			{
				FactID:     "f1",
				Source:     "health_check",
				Claim:      "API is reachable",
				VerifiedAt: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC),
			},
		},
		Unknowns: []contracts.Unknown{
			{
				ID:          "u1",
				Description: "API rate limits unknown",
				Impact:      contracts.UnknownImpactDegrading,
			},
		},
		Confidence:        0.85,
		EvidenceRefs:      []string{"sha256:abc123"},
		BlockingQuestions: []string{"What is the rate limit?"},
		RequestedBackend:  "docker",
		RequestedProfile:  "net-limited",
	}

	data, err := json.Marshal(step)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded contracts.PlanStep
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Justification != "Required for data sync" {
		t.Fatalf("justification mismatch: %s", decoded.Justification)
	}
	if decoded.Confidence != 0.85 {
		t.Fatalf("confidence mismatch: %f", decoded.Confidence)
	}
	if decoded.RequestedBackend != "docker" {
		t.Fatalf("backend mismatch: %s", decoded.RequestedBackend)
	}
	if len(decoded.FactSet) != 1 || decoded.FactSet[0].FactID != "f1" {
		t.Fatalf("fact_set mismatch: %v", decoded.FactSet)
	}
	if len(decoded.Unknowns) != 1 || decoded.Unknowns[0].ID != "u1" {
		t.Fatalf("unknowns mismatch: %v", decoded.Unknowns)
	}
	if len(decoded.BlockingQuestions) != 1 {
		t.Fatalf("blocking_questions mismatch: %v", decoded.BlockingQuestions)
	}
}

func TestPlanSpec_TruthAnnotation_Roundtrip(t *testing.T) {
	plan := contracts.PlanSpec{
		ID:      "plan-1",
		Version: "1.0.0",
		Hash:    "sha256:deadbeef",
		Truth: &contracts.TruthAnnotation{
			Confidence:   0.7,
			Assumptions:  []string{"Network available"},
			EvidenceRefs: []string{"sha256:evidence1"},
		},
	}

	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded contracts.PlanSpec
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Truth == nil {
		t.Fatal("expected truth annotation")
	}
	if decoded.Truth.Confidence != 0.7 {
		t.Fatalf("confidence mismatch: %f", decoded.Truth.Confidence)
	}
	if len(decoded.Truth.Assumptions) != 1 {
		t.Fatalf("assumptions mismatch: %v", decoded.Truth.Assumptions)
	}
}

func TestPlanSpec_NoTruth_BackwardCompat(t *testing.T) {
	oldJSON := `{"id": "plan-1", "version": "1.0.0", "hash": "sha256:abc"}`
	var plan contracts.PlanSpec
	if err := json.Unmarshal([]byte(oldJSON), &plan); err != nil {
		t.Fatalf("failed to unmarshal old PlanSpec: %v", err)
	}
	if plan.Truth != nil {
		t.Fatal("expected nil truth for old JSON")
	}
}

// ──────────────────────────────────────────────────────────────
// FactRef JSON test
// ──────────────────────────────────────────────────────────────

func TestFactRef_JSON_OmitsEmptyStringFields(t *testing.T) {
	f := contracts.FactRef{
		FactID: "f1",
		Source: "test",
		Claim:  "something is true",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	// Hash (string with omitempty) should be omitted when empty.
	if strings.Contains(s, `"hash"`) {
		t.Fatalf("expected hash omitted, got %s", s)
	}
	// fact_id, source, claim must be present.
	if !strings.Contains(s, `"fact_id"`) {
		t.Fatalf("expected fact_id present, got %s", s)
	}
}
