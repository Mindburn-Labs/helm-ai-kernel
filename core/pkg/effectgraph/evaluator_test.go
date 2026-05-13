package effectgraph_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectgraph"
)

// mockPolicy is a test policy evaluator that returns configurable verdicts per step.
type mockPolicy struct {
	verdicts map[string]contracts.Verdict // stepID → verdict
}

func (m *mockPolicy) EvaluateStep(_ context.Context, step *contracts.PlanStep, _ string) (*contracts.DecisionRecord, error) {
	verdict, ok := m.verdicts[step.ID]
	if !ok {
		verdict = contracts.VerdictAllow
	}
	return &contracts.DecisionRecord{
		ID:         "dec-" + step.ID,
		Verdict:    string(verdict),
		ReasonCode: "TEST",
	}, nil
}

func (m *mockPolicy) IssueIntent(_ context.Context, decision *contracts.DecisionRecord, step *contracts.PlanStep) (*contracts.AuthorizedExecutionIntent, error) {
	if decision.Verdict != string(contracts.VerdictAllow) {
		return nil, fmt.Errorf("cannot issue intent for %s", decision.Verdict)
	}
	return &contracts.AuthorizedExecutionIntent{
		ID:         "intent-" + step.ID,
		DecisionID: decision.ID,
	}, nil
}

func linearDAG() *contracts.PlanSpec {
	return &contracts.PlanSpec{
		ID: "plan-1",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "a", EffectType: "EXECUTE"},
				{ID: "b", EffectType: "WRITE"},
				{ID: "c", EffectType: "SOFTWARE_PUBLISH"},
			},
			Edges: []contracts.Edge{
				{From: "a", To: "b", Type: "requires"},
				{From: "b", To: "c", Type: "requires"},
			},
		},
	}
}

func TestEvaluate_AllAllow(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{
		verdicts: map[string]contracts.Verdict{},
	})

	result, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  linearDAG(),
		Actor: "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.AllowedSteps) != 3 {
		t.Fatalf("expected 3 allowed, got %d", len(result.AllowedSteps))
	}
	if len(result.DeniedSteps) != 0 {
		t.Fatalf("expected 0 denied, got %d", len(result.DeniedSteps))
	}
	if len(result.BlockedSteps) != 0 {
		t.Fatalf("expected 0 blocked, got %d", len(result.BlockedSteps))
	}
	if result.GraphHash == "" {
		t.Fatal("expected non-empty graph hash")
	}

	// Check that intents were issued for all steps.
	for _, stepID := range []string{"a", "b", "c"} {
		v := result.Verdicts[stepID]
		if v.Intent == nil {
			t.Fatalf("expected intent for step %s", stepID)
		}
		if v.Profile == nil {
			t.Fatalf("expected profile for step %s", stepID)
		}
	}
}

func TestEvaluate_DenyCascade(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{
		verdicts: map[string]contracts.Verdict{
			"a": contracts.VerdictDeny, // deny the root
		},
	})

	result, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  linearDAG(),
		Actor: "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// "a" is denied directly, "b" and "c" blocked by cascade.
	if len(result.DeniedSteps) != 1 || result.DeniedSteps[0] != "a" {
		t.Fatalf("expected [a] denied, got %v", result.DeniedSteps)
	}
	if len(result.BlockedSteps) != 2 {
		t.Fatalf("expected 2 blocked, got %d: %v", len(result.BlockedSteps), result.BlockedSteps)
	}
	if len(result.AllowedSteps) != 0 {
		t.Fatalf("expected 0 allowed, got %d", len(result.AllowedSteps))
	}

	// Check blocked-by metadata.
	vb := result.Verdicts["b"]
	if len(vb.BlockedBy) != 1 || vb.BlockedBy[0] != "a" {
		t.Fatalf("expected b blocked by [a], got %v", vb.BlockedBy)
	}
	vc := result.Verdicts["c"]
	if len(vc.BlockedBy) != 1 || vc.BlockedBy[0] != "b" {
		t.Fatalf("expected c blocked by [b], got %v", vc.BlockedBy)
	}
}

func TestEvaluate_DenyMiddle(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{
		verdicts: map[string]contracts.Verdict{
			"b": contracts.VerdictDeny, // deny the middle step
		},
	})

	result, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  linearDAG(),
		Actor: "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// "a" allowed, "b" denied, "c" blocked.
	if len(result.AllowedSteps) != 1 || result.AllowedSteps[0] != "a" {
		t.Fatalf("expected [a] allowed, got %v", result.AllowedSteps)
	}
	if len(result.DeniedSteps) != 1 || result.DeniedSteps[0] != "b" {
		t.Fatalf("expected [b] denied, got %v", result.DeniedSteps)
	}
	if len(result.BlockedSteps) != 1 || result.BlockedSteps[0] != "c" {
		t.Fatalf("expected [c] blocked, got %v", result.BlockedSteps)
	}
}

func TestEvaluate_Escalate(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{
		verdicts: map[string]contracts.Verdict{
			"b": contracts.VerdictEscalate,
		},
	})

	result, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  linearDAG(),
		Actor: "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.EscalateSteps) != 1 || result.EscalateSteps[0] != "b" {
		t.Fatalf("expected [b] escalated, got %v", result.EscalateSteps)
	}
	// "a" should be allowed, "b" escalated, "c" still allowed (escalate does not cascade deny).
	if len(result.AllowedSteps) != 2 {
		t.Fatalf("expected 2 allowed, got %d: %v", len(result.AllowedSteps), result.AllowedSteps)
	}
}

func TestEvaluate_DiamondDAG(t *testing.T) {
	plan := &contracts.PlanSpec{
		ID: "plan-diamond",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "a", EffectType: "EXECUTE"},
				{ID: "b", EffectType: "EXECUTE"},
				{ID: "c", EffectType: "EXECUTE"},
				{ID: "d", EffectType: "EXECUTE"},
			},
			Edges: []contracts.Edge{
				{From: "a", To: "b"},
				{From: "a", To: "c"},
				{From: "b", To: "d"},
				{From: "c", To: "d"},
			},
		},
	}

	eval := effectgraph.NewGraphEvaluator(&mockPolicy{
		verdicts: map[string]contracts.Verdict{
			"a": contracts.VerdictDeny,
		},
	})

	result, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  plan,
		Actor: "test-user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// All downstream blocked.
	if len(result.DeniedSteps) != 1 {
		t.Fatalf("expected 1 denied, got %d", len(result.DeniedSteps))
	}
	if len(result.BlockedSteps) != 3 {
		t.Fatalf("expected 3 blocked, got %d: %v", len(result.BlockedSteps), result.BlockedSteps)
	}
}

func TestEvaluate_GraphHash_Deterministic(t *testing.T) {
	policy := &mockPolicy{verdicts: map[string]contracts.Verdict{}}
	eval := effectgraph.NewGraphEvaluator(policy)

	r1, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  linearDAG(),
		Actor: "user",
	})
	r2, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  linearDAG(),
		Actor: "user",
	})

	if r1.GraphHash != r2.GraphHash {
		t.Fatalf("graph hash not deterministic: %s != %s", r1.GraphHash, r2.GraphHash)
	}
}

func TestEvaluate_NilPlan(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{})
	_, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{})
	if err == nil {
		t.Fatal("expected error for nil plan")
	}
}

func TestEvaluate_IndependentNodes(t *testing.T) {
	plan := &contracts.PlanSpec{
		ID: "plan-independent",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "x", EffectType: "READ"},
				{ID: "y", EffectType: "WRITE"},
				{ID: "z", EffectType: "EXECUTE"},
			},
			Edges: nil,
		},
	}

	eval := effectgraph.NewGraphEvaluator(&mockPolicy{
		verdicts: map[string]contracts.Verdict{
			"y": contracts.VerdictDeny,
		},
	})

	result, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  plan,
		Actor: "user",
	})
	if err != nil {
		t.Fatal(err)
	}

	// No cascade: x and z allowed, y denied.
	if len(result.AllowedSteps) != 2 {
		t.Fatalf("expected 2 allowed, got %d", len(result.AllowedSteps))
	}
	if len(result.DeniedSteps) != 1 {
		t.Fatalf("expected 1 denied, got %d", len(result.DeniedSteps))
	}
	if len(result.BlockedSteps) != 0 {
		t.Fatalf("expected 0 blocked, got %d", len(result.BlockedSteps))
	}
}

func TestEvaluate_TruthSummary(t *testing.T) {
	plan := &contracts.PlanSpec{
		ID: "plan-truth",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{
					ID:          "a",
					EffectType:  "EXECUTE",
					Assumptions: []string{"env is ready"},
					Unknowns: []contracts.Unknown{
						{ID: "u1", Impact: contracts.UnknownImpactBlocking},
					},
				},
				{
					ID:          "b",
					EffectType:  "WRITE",
					Assumptions: []string{"disk has space"},
				},
			},
		},
	}

	eval := effectgraph.NewGraphEvaluator(&mockPolicy{})
	result, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  plan,
		Actor: "user",
	})

	if result.TruthSummary == nil {
		t.Fatal("expected truth summary")
	}
	if len(result.TruthSummary.Assumptions) != 2 {
		t.Fatalf("expected 2 assumptions, got %d", len(result.TruthSummary.Assumptions))
	}
	if len(result.TruthSummary.Unknowns) != 1 {
		t.Fatalf("expected 1 unknown, got %d", len(result.TruthSummary.Unknowns))
	}
}
