package delivery

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinal_DeliveryStrategyConstants(t *testing.T) {
	strategies := []DeliveryStrategy{StrategyShadow, StrategyCanary, StrategyBlueGreen}
	seen := map[DeliveryStrategy]bool{}
	for _, s := range strategies {
		if seen[s] {
			t.Fatalf("duplicate: %s", s)
		}
		seen[s] = true
	}
}

func TestFinal_DeliveryStatusConstants(t *testing.T) {
	statuses := []DeliveryStatus{DeliveryPending, DeliveryInProgress, DeliveryPromoted, DeliveryRolledBack, DeliveryFailed}
	if len(statuses) != 5 {
		t.Fatal("expected 5 statuses")
	}
}

func TestFinal_DeliveryPlanJSONRoundTrip(t *testing.T) {
	plan := DeliveryPlan{PlanID: "p1", Strategy: StrategyCanary, CurrentStage: 1}
	data, _ := json.Marshal(plan)
	var got DeliveryPlan
	json.Unmarshal(data, &got)
	if got.PlanID != "p1" || got.Strategy != StrategyCanary {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DeliveryStageJSONRoundTrip(t *testing.T) {
	stage := DeliveryStage{StageID: "s1", Weight: 10, AutoPromote: true}
	data, _ := json.Marshal(stage)
	var got DeliveryStage
	json.Unmarshal(data, &got)
	if got.Weight != 10 || !got.AutoPromote {
		t.Fatal("stage round-trip")
	}
}

func TestFinal_PromotionGateJSONRoundTrip(t *testing.T) {
	gate := PromotionGate{MetricName: "error_rate", Threshold: 0.01, Operator: "lt"}
	data, _ := json.Marshal(gate)
	var got PromotionGate
	json.Unmarshal(data, &got)
	if got.MetricName != "error_rate" || got.Operator != "lt" {
		t.Fatal("gate round-trip")
	}
}

func TestFinal_RollbackPolicyJSONRoundTrip(t *testing.T) {
	rp := RollbackPolicy{AutoRollback: true, Conditions: []RollbackCondition{{MetricName: "err", Threshold: 5}}}
	data, _ := json.Marshal(rp)
	var got RollbackPolicy
	json.Unmarshal(data, &got)
	if !got.AutoRollback || len(got.Conditions) != 1 {
		t.Fatal("rollback policy round-trip")
	}
}

func TestFinal_ShadowResultJSONRoundTrip(t *testing.T) {
	sr := ShadowResult{RequestID: "r1", CurrentOutput: "h1", CandidateOutput: "h2", Diverged: true}
	data, _ := json.Marshal(sr)
	var got ShadowResult
	json.Unmarshal(data, &got)
	if !got.Diverged || got.RequestID != "r1" {
		t.Fatal("shadow result round-trip")
	}
}

func TestFinal_ComputeHashDeterministic(t *testing.T) {
	plan := &DeliveryPlan{PlanID: "p1", Strategy: StrategyCanary, Stages: []DeliveryStage{{StageID: "s1"}}}
	plan.ComputeHash()
	h1 := plan.ContentHash
	plan.ComputeHash()
	h2 := plan.ContentHash
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
}

func TestFinal_ComputeHashPrefix(t *testing.T) {
	plan := &DeliveryPlan{PlanID: "p1", Strategy: StrategyCanary, Stages: []DeliveryStage{{StageID: "s1"}}}
	plan.ComputeHash()
	if !strings.HasPrefix(plan.ContentHash, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_ComputeHashExcludesItself(t *testing.T) {
	plan := &DeliveryPlan{PlanID: "p1", Strategy: StrategyCanary, Stages: []DeliveryStage{{StageID: "s1"}}}
	plan.ContentHash = "garbage"
	plan.ComputeHash()
	if plan.ContentHash == "garbage" {
		t.Fatal("hash should be recomputed")
	}
}

func TestFinal_NewDeliveryController(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	if ctrl == nil {
		t.Fatal("nil controller")
	}
}

func TestFinal_StartEmptyPlanFails(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	err := ctrl.Start(&DeliveryPlan{PlanID: "p1"})
	if err == nil {
		t.Fatal("empty stages should fail")
	}
}

func TestFinal_StartSetsStatus(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	if plan.Status != DeliveryInProgress {
		t.Fatal("status should be IN_PROGRESS")
	}
}

func TestFinal_GetPlanExists(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	got, ok := ctrl.GetPlan("p1")
	if !ok || got.PlanID != "p1" {
		t.Fatal("plan not found")
	}
}

func TestFinal_GetPlanMissing(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	_, ok := ctrl.GetPlan("nope")
	if ok {
		t.Fatal("should not find")
	}
}

func TestFinal_RollbackSetsStatus(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	ctrl.Rollback("p1", "bad metrics")
	if plan.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", plan.Status)
	}
}

func TestFinal_RollbackMissingPlanFails(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	err := ctrl.Rollback("nope", "reason")
	if err == nil {
		t.Fatal("should fail on missing plan")
	}
}

func TestFinal_PromoteMissingPlanFails(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	err := ctrl.Promote("nope")
	if err == nil {
		t.Fatal("should fail")
	}
}

func TestFinal_EvaluateGateLt(t *testing.T) {
	if !evaluateGate(0.5, 1.0, "lt") {
		t.Fatal("0.5 < 1.0 should pass")
	}
}

func TestFinal_EvaluateGateGt(t *testing.T) {
	if !evaluateGate(2.0, 1.0, "gt") {
		t.Fatal("2.0 > 1.0 should pass")
	}
}

func TestFinal_EvaluateGateLte(t *testing.T) {
	if !evaluateGate(1.0, 1.0, "lte") {
		t.Fatal("1.0 <= 1.0 should pass")
	}
}

func TestFinal_EvaluateGateGte(t *testing.T) {
	if !evaluateGate(1.0, 1.0, "gte") {
		t.Fatal("1.0 >= 1.0 should pass")
	}
}

func TestFinal_EvaluateGateUnknown(t *testing.T) {
	if evaluateGate(1.0, 1.0, "eq") {
		t.Fatal("unknown operator should fail")
	}
}

func TestFinal_PromoteFinalStage(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	err := ctrl.Promote("p1")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != DeliveryPromoted {
		t.Fatalf("expected PROMOTED, got %s", plan.Status)
	}
}

func TestFinal_PromoteAdvancesStage(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}, {StageID: "s2"}}}
	ctrl.Start(plan)
	ctrl.Promote("p1")
	if plan.CurrentStage != 1 {
		t.Fatal("should advance to stage 1")
	}
}

func TestFinal_WithClockSetsTime(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctrl := NewDeliveryController(nil)
	ctrl.WithClock(func() time.Time { return fixed })
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	if !plan.StartedAt.Equal(fixed) {
		t.Fatal("clock not injected")
	}
}

func TestFinal_RollbackConditionJSONRoundTrip(t *testing.T) {
	rc := RollbackCondition{MetricName: "error_rate", Threshold: 0.05, Operator: "gt"}
	data, _ := json.Marshal(rc)
	var got RollbackCondition
	json.Unmarshal(data, &got)
	if got.MetricName != "error_rate" {
		t.Fatal("round-trip")
	}
}

func TestFinal_PromoteOnRolledBackFails(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	ctrl.Rollback("p1", "reason")
	err := ctrl.Promote("p1")
	if err == nil {
		t.Fatal("should fail on rolled back plan")
	}
}

func TestFinal_DeliveryPlanCompletedAtSet(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	ctrl.Promote("p1")
	if plan.CompletedAt.IsZero() {
		t.Fatal("completedAt should be set")
	}
}

func TestFinal_PlanContentHashUpdated(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	plan := &DeliveryPlan{PlanID: "p1", Stages: []DeliveryStage{{StageID: "s1"}}}
	ctrl.Start(plan)
	h1 := plan.ContentHash
	ctrl.Promote("p1")
	if plan.ContentHash == h1 {
		t.Fatal("hash should change after promote")
	}
}

func TestFinal_CheckPromotionMissingPlan(t *testing.T) {
	ctrl := NewDeliveryController(nil)
	_, _, err := ctrl.CheckPromotion(nil, "nope")
	if err == nil {
		t.Fatal("should error on missing plan")
	}
}
