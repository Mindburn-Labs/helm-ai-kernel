package delivery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

type fakeMetrics struct {
	values map[string]float64
}

func (s *fakeMetrics) GetMetric(_ context.Context, name string) (float64, error) {
	v, ok := s.values[name]
	if !ok {
		return 0, fmt.Errorf("metric %s not found", name)
	}
	return v, nil
}

func newTestController(metrics map[string]float64) *DeliveryController {
	c := NewDeliveryController(&fakeMetrics{values: metrics})
	c.WithClock(fixedClock)
	return c
}

func singleStagePlan(planID string) *DeliveryPlan {
	return &DeliveryPlan{
		PlanID:   planID,
		Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{StageID: "s1", Weight: 10, MinDuration: time.Minute},
		},
	}
}

func TestStartPlanSetsStatus(t *testing.T) {
	c := newTestController(nil)
	p := singleStagePlan("p1")
	if err := c.Start(p); err != nil {
		t.Fatalf("start: %v", err)
	}
	got, ok := c.GetPlan("p1")
	if !ok || got.Status != DeliveryInProgress {
		t.Fatalf("expected IN_PROGRESS, got %v", got)
	}
}

func TestStartPlanRejectsEmpty(t *testing.T) {
	c := newTestController(nil)
	err := c.Start(&DeliveryPlan{PlanID: "p"})
	if err == nil || !strings.Contains(err.Error(), "no stages") {
		t.Fatalf("expected no-stages error, got %v", err)
	}
}

func TestCheckPromotionSoakTimeNotMet(t *testing.T) {
	c := newTestController(map[string]float64{})
	p := singleStagePlan("p1")
	c.Start(p)
	can, reason, err := c.CheckPromotion(context.Background(), "p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if can {
		t.Fatal("soak time not met, should not promote")
	}
	if !strings.Contains(reason, "soak time") {
		t.Fatalf("expected soak time reason, got %s", reason)
	}
}

func TestCheckPromotionGateFails(t *testing.T) {
	c := newTestController(map[string]float64{"error_rate": 0.05})
	// Use clock that is far in the future to bypass soak
	c.WithClock(func() time.Time { return fixedTime.Add(time.Hour) })
	p := &DeliveryPlan{
		PlanID:   "p1",
		Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{StageID: "s1", Weight: 10, MinDuration: time.Minute,
				GateMetrics: []PromotionGate{{MetricName: "error_rate", Threshold: 0.01, Operator: "lt"}}},
		},
	}
	c.Start(p)
	can, _, _ := c.CheckPromotion(context.Background(), "p1")
	if can {
		t.Fatal("gate should fail when error_rate > threshold")
	}
}

func TestCheckPromotionGatePasses(t *testing.T) {
	c := newTestController(map[string]float64{"error_rate": 0.005})
	p := &DeliveryPlan{
		PlanID:   "p1",
		Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{StageID: "s1", Weight: 10, MinDuration: time.Minute,
				GateMetrics: []PromotionGate{{MetricName: "error_rate", Threshold: 0.01, Operator: "lt"}}},
		},
	}
	c.Start(p)
	// Advance clock past soak time after start.
	c.WithClock(func() time.Time { return fixedTime.Add(time.Hour) })
	can, _, _ := c.CheckPromotion(context.Background(), "p1")
	if !can {
		t.Fatal("gate should pass when error_rate < threshold")
	}
}

func TestPromoteAdvancesStage(t *testing.T) {
	c := newTestController(nil)
	p := &DeliveryPlan{
		PlanID:   "p1",
		Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{StageID: "s1", Weight: 10, MinDuration: 0},
			{StageID: "s2", Weight: 50, MinDuration: 0},
		},
	}
	c.Start(p)
	c.Promote("p1")
	got, _ := c.GetPlan("p1")
	if got.CurrentStage != 1 || got.Stages[1].Status != DeliveryInProgress {
		t.Fatalf("expected stage 1 in progress, got stage=%d status=%s", got.CurrentStage, got.Stages[1].Status)
	}
}

func TestPromoteFinalStageCompletes(t *testing.T) {
	c := newTestController(nil)
	p := singleStagePlan("p1")
	c.Start(p)
	c.Promote("p1")
	got, _ := c.GetPlan("p1")
	if got.Status != DeliveryPromoted {
		t.Fatalf("expected PROMOTED, got %s", got.Status)
	}
}

func TestRollbackSetsStatus(t *testing.T) {
	c := newTestController(nil)
	c.Start(singleStagePlan("p1"))
	c.Rollback("p1", "broken")
	got, _ := c.GetPlan("p1")
	if got.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", got.Status)
	}
}

func TestRollbackNotFound(t *testing.T) {
	c := newTestController(nil)
	err := c.Rollback("nonexistent", "r")
	if err == nil {
		t.Fatal("expected error for nonexistent plan")
	}
}

func TestCheckRollbackTriggered(t *testing.T) {
	c := newTestController(map[string]float64{"error_rate": 0.1})
	p := &DeliveryPlan{
		PlanID:   "p1",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s1"}},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions:   []RollbackCondition{{MetricName: "error_rate", Threshold: 0.05, Operator: "gt"}},
		},
	}
	c.Start(p)
	shouldRollback, _, _ := c.CheckRollback(context.Background(), "p1")
	if !shouldRollback {
		t.Fatal("rollback condition should trigger")
	}
}

func TestCheckRollbackNotTriggered(t *testing.T) {
	c := newTestController(map[string]float64{"error_rate": 0.01})
	p := &DeliveryPlan{
		PlanID:   "p1",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s1"}},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions:   []RollbackCondition{{MetricName: "error_rate", Threshold: 0.05, Operator: "gt"}},
		},
	}
	c.Start(p)
	shouldRollback, _, _ := c.CheckRollback(context.Background(), "p1")
	if shouldRollback {
		t.Fatal("rollback condition should not trigger")
	}
}

func TestDeliveryPlanComputeHash(t *testing.T) {
	p := singleStagePlan("p1")
	p.ComputeHash()
	if p.ContentHash == "" || !strings.HasPrefix(p.ContentHash, "sha256:") {
		t.Fatalf("expected sha256: hash, got %s", p.ContentHash)
	}
}

func TestGetPlanNotFound(t *testing.T) {
	c := newTestController(nil)
	_, ok := c.GetPlan("missing")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestDeliveryStrategyConstants(t *testing.T) {
	if StrategyShadow != "SHADOW" || StrategyCanary != "CANARY" || StrategyBlueGreen != "BLUE_GREEN" {
		t.Fatal("strategy constants mismatch")
	}
}

func TestPromoteNotInProgressFails(t *testing.T) {
	c := newTestController(nil)
	c.Start(singleStagePlan("p1"))
	c.Promote("p1") // completes the single-stage plan
	err := c.Promote("p1")
	if err == nil || !strings.Contains(err.Error(), "not in progress") {
		t.Fatalf("expected not-in-progress error, got %v", err)
	}
}
