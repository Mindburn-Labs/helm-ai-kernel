package effectgraph_test

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effectgraph"
)

func singleNodeDAG(id, effectType string) *contracts.PlanSpec {
	return &contracts.PlanSpec{
		ID: "plan-single",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{{ID: id, EffectType: effectType}},
		},
	}
}

func forkDAG() *contracts.PlanSpec {
	return &contracts.PlanSpec{
		ID: "plan-fork",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "root", EffectType: "EXECUTE"},
				{ID: "left", EffectType: "WRITE"},
				{ID: "right", EffectType: "READ"},
			},
			Edges: []contracts.Edge{
				{From: "root", To: "left"},
				{From: "root", To: "right"},
			},
		},
	}
}

func TestEvaluate_SingleNodeAllow(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{}})
	r, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("s1", "READ"), Actor: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.AllowedSteps) != 1 || r.AllowedSteps[0] != "s1" {
		t.Fatalf("expected [s1] allowed, got %v", r.AllowedSteps)
	}
}

func TestEvaluate_SingleNodeDeny(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"s1": contracts.VerdictDeny}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("s1", "WRITE"), Actor: "u"})
	if len(r.DeniedSteps) != 1 {
		t.Fatalf("expected 1 denied, got %d", len(r.DeniedSteps))
	}
}

func TestEvaluate_SingleNodeEscalate(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"s1": contracts.VerdictEscalate}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("s1", "EXECUTE"), Actor: "u"})
	if len(r.EscalateSteps) != 1 {
		t.Fatalf("expected 1 escalated, got %d", len(r.EscalateSteps))
	}
}

func TestEvaluate_ForkAllAllow(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{}})
	r, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: forkDAG(), Actor: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.AllowedSteps) != 3 {
		t.Fatalf("expected 3 allowed, got %d", len(r.AllowedSteps))
	}
}

func TestEvaluate_ForkRootDenied(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"root": contracts.VerdictDeny}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: forkDAG(), Actor: "u"})
	if len(r.DeniedSteps) != 1 {
		t.Fatalf("expected 1 denied, got %d", len(r.DeniedSteps))
	}
	if len(r.BlockedSteps) != 2 {
		t.Fatalf("expected 2 blocked, got %d", len(r.BlockedSteps))
	}
}

func TestEvaluate_ForkLeafDenied(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"left": contracts.VerdictDeny}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: forkDAG(), Actor: "u"})
	if len(r.AllowedSteps) != 2 {
		t.Fatalf("expected 2 allowed, got %d", len(r.AllowedSteps))
	}
	if len(r.DeniedSteps) != 1 || r.DeniedSteps[0] != "left" {
		t.Fatalf("expected [left] denied, got %v", r.DeniedSteps)
	}
}

func TestEvaluate_NilDAG(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{})
	_, err := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: &contracts.PlanSpec{ID: "p1"}})
	if err == nil {
		t.Fatal("expected error for nil DAG")
	}
}

func TestEvaluate_GraphHashFormat(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("x", "READ"), Actor: "u"})
	if len(r.GraphHash) < 7 || r.GraphHash[:7] != "sha256:" {
		t.Fatalf("graph hash should start with sha256: prefix, got %s", r.GraphHash)
	}
}

func TestEvaluate_VerdictMapPopulated(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: linearDAG(), Actor: "u"})
	for _, id := range []string{"a", "b", "c"} {
		if _, ok := r.Verdicts[id]; !ok {
			t.Fatalf("verdict missing for step %s", id)
		}
	}
}

func TestEvaluate_AllowedStepHasProfile(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("s1", "EXECUTE"), Actor: "u"})
	v := r.Verdicts["s1"]
	if v.Profile == nil {
		t.Fatal("allowed step should have an execution profile")
	}
	if v.Profile.Backend == "" {
		t.Fatal("profile backend should not be empty")
	}
}

func TestEvaluate_DeniedStepNoIntent(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"s1": contracts.VerdictDeny}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("s1", "WRITE"), Actor: "u"})
	v := r.Verdicts["s1"]
	if v.Intent != nil {
		t.Fatal("denied step should not have an intent")
	}
}

func TestEvaluate_TruthSummaryConfidenceReduced(t *testing.T) {
	plan := &contracts.PlanSpec{
		ID: "plan-conf",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{
				{ID: "a", EffectType: "READ"},
				{ID: "b", EffectType: "WRITE"},
			},
		},
	}
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"b": contracts.VerdictDeny}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: plan, Actor: "u"})
	if r.TruthSummary == nil {
		t.Fatal("expected truth summary")
	}
	if r.TruthSummary.Confidence >= 1.0 {
		t.Fatalf("confidence should be reduced when steps denied, got %f", r.TruthSummary.Confidence)
	}
}

func TestEvaluationResult_EmptyLists(t *testing.T) {
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: singleNodeDAG("x", "READ"), Actor: "u"})
	if len(r.BlockedSteps) != 0 || len(r.DeniedSteps) != 0 || len(r.EscalateSteps) != 0 {
		t.Fatal("no steps should be blocked/denied/escalated")
	}
}

func TestNodeVerdict_BlockedByField(t *testing.T) {
	plan := &contracts.PlanSpec{
		ID: "plan-chain",
		DAG: &contracts.DAG{
			Nodes: []contracts.PlanStep{{ID: "p", EffectType: "EXEC"}, {ID: "q", EffectType: "EXEC"}},
			Edges: []contracts.Edge{{From: "p", To: "q"}},
		},
	}
	eval := effectgraph.NewGraphEvaluator(&mockPolicy{verdicts: map[string]contracts.Verdict{"p": contracts.VerdictDeny}})
	r, _ := eval.Evaluate(context.Background(), &effectgraph.EvaluationRequest{Plan: plan, Actor: "u"})
	vq := r.Verdicts["q"]
	if len(vq.BlockedBy) == 0 || vq.BlockedBy[0] != "p" {
		t.Fatalf("q should be blocked by p, got %v", vq.BlockedBy)
	}
}
