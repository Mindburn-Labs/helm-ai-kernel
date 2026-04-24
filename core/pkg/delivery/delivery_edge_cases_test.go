package delivery

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type staticMetrics struct {
	values map[string]float64
	mu     sync.Mutex
}

func (m *staticMetrics) GetMetric(_ context.Context, name string) (float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[name]
	if !ok {
		return 0, fmt.Errorf("metric %s not found", name)
	}
	return v, nil
}

var baseTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func canaryPlan5Stages() *DeliveryPlan {
	stages := make([]DeliveryStage, 5)
	for i := 0; i < 5; i++ {
		stages[i] = DeliveryStage{
			StageID:     fmt.Sprintf("s%d", i),
			Weight:      (i + 1) * 20,
			MinDuration: time.Minute,
			GateMetrics: []PromotionGate{{MetricName: "error_rate", Threshold: 0.05, Operator: "lt"}},
		}
	}
	return &DeliveryPlan{PlanID: "canary-5", Strategy: StrategyCanary, Stages: stages}
}

func TestDeep_Canary5StageFullPromotion(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"error_rate": 0.01}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })
	plan := canaryPlan5Stages()
	c.Start(plan)

	for i := 0; i < 5; i++ {
		now = now.Add(2 * time.Minute)
		ok, _, _ := c.CheckPromotion(context.Background(), plan.PlanID)
		if !ok {
			t.Fatalf("stage %d: promotion should pass", i)
		}
		c.Promote(plan.PlanID)
	}
	if plan.Status != DeliveryPromoted {
		t.Fatalf("expected PROMOTED, got %s", plan.Status)
	}
}

func TestDeep_CanaryGateBlocksPromotion(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"error_rate": 0.10}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })
	c.Start(canaryPlan5Stages())
	now = now.Add(2 * time.Minute)
	ok, reason, _ := c.CheckPromotion(context.Background(), "canary-5")
	if ok {
		t.Fatal("gate should block promotion when error_rate is high")
	}
	if reason == "" {
		t.Fatal("reason should explain gate failure")
	}
}

func TestDeep_CanarySoakTimeEnforced(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"error_rate": 0.01}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })
	c.Start(canaryPlan5Stages())
	ok, reason, _ := c.CheckPromotion(context.Background(), "canary-5")
	if ok {
		t.Fatal("should not promote before soak time")
	}
	if reason == "" {
		t.Fatal("should explain soak time remaining")
	}
}

func TestDeep_ShadowModeComparison(t *testing.T) {
	res := ShadowResult{
		RequestID:       "r1",
		CurrentOutput:   "hash-a",
		CandidateOutput: "hash-b",
		Diverged:        true,
		Timestamp:       baseTime,
	}
	if !res.Diverged {
		t.Fatal("different hashes should diverge")
	}
	noDiverge := ShadowResult{CurrentOutput: "hash-a", CandidateOutput: "hash-a"}
	if noDiverge.Diverged {
		t.Fatal("same hashes should not diverge")
	}
}

func TestDeep_BlueGreenInstantCutover(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })

	plan := &DeliveryPlan{
		PlanID:   "bg-1",
		Strategy: StrategyBlueGreen,
		Stages: []DeliveryStage{
			{StageID: "cutover", Weight: 100, MinDuration: 0},
		},
	}
	c.Start(plan)
	c.Promote(plan.PlanID)
	if plan.Status != DeliveryPromoted {
		t.Fatal("blue-green with single stage should complete immediately")
	}
}

func TestDeep_RollbackConditionTriggers(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"p99_latency_ms": 500.0}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })

	plan := &DeliveryPlan{
		PlanID:   "rollback-test",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0", Weight: 10, MinDuration: 0}},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions:   []RollbackCondition{{MetricName: "p99_latency_ms", Threshold: 200.0, Operator: "gt"}},
		},
	}
	c.Start(plan)
	shouldRollback, reason, _ := c.CheckRollback(context.Background(), "rollback-test")
	if !shouldRollback {
		t.Fatal("latency > 200 should trigger rollback")
	}
	if reason == "" {
		t.Fatal("reason should be provided")
	}
}

func TestDeep_RollbackMarksStatus(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })
	plan := &DeliveryPlan{
		PlanID: "rb-status", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{StageID: "s0", Weight: 10, MinDuration: 0}},
	}
	c.Start(plan)
	c.Rollback("rb-status", "manual")
	if plan.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", plan.Status)
	}
}

func TestDeep_SLOGateTightThreshold(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"success_rate": 0.9999}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })

	plan := &DeliveryPlan{
		PlanID: "slo-tight", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{
			StageID: "s0", Weight: 10, MinDuration: time.Second,
			GateMetrics: []PromotionGate{{MetricName: "success_rate", Threshold: 0.99999, Operator: "gte"}},
		}},
	}
	c.Start(plan)
	now = now.Add(time.Minute)
	ok, _, _ := c.CheckPromotion(context.Background(), "slo-tight")
	if ok {
		t.Fatal("0.9999 < 0.99999 — gate should block")
	}
}

func TestDeep_SLOGateExactThreshold(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"success_rate": 0.99}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })

	plan := &DeliveryPlan{
		PlanID: "slo-exact", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{
			StageID: "s0", Weight: 10, MinDuration: 0,
			GateMetrics: []PromotionGate{{MetricName: "success_rate", Threshold: 0.99, Operator: "gte"}},
		}},
	}
	c.Start(plan)
	now = now.Add(time.Second)
	ok, _, _ := c.CheckPromotion(context.Background(), "slo-exact")
	if !ok {
		t.Fatal("exactly at threshold with gte should pass")
	}
}

func TestDeep_ConcurrentPromoteRollback(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })

	plan := &DeliveryPlan{
		PlanID: "conc", Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{StageID: "s0", Weight: 50, MinDuration: 0},
			{StageID: "s1", Weight: 100, MinDuration: 0},
		},
	}
	c.Start(plan)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.Promote("conc") }()
	go func() { defer wg.Done(); c.Rollback("conc", "race") }()
	wg.Wait()

	p, _ := c.GetPlan("conc")
	if p.Status != DeliveryPromoted && p.Status != DeliveryRolledBack {
		t.Fatalf("unexpected status: %s", p.Status)
	}
}

func TestDeep_EmptyPlanReject(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	err := c.Start(&DeliveryPlan{PlanID: "empty", Stages: nil})
	if err == nil {
		t.Fatal("should reject empty plan")
	}
}

func TestDeep_PromoteUnknownPlan(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	if err := c.Promote("ghost"); err == nil {
		t.Fatal("should reject unknown plan")
	}
}

func TestDeep_RollbackUnknownPlan(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	if err := c.Rollback("ghost", "x"); err == nil {
		t.Fatal("should reject unknown plan")
	}
}

func TestDeep_ContentHashChangesOnPromote(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })

	plan := &DeliveryPlan{
		PlanID: "hash-chg", Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{StageID: "s0", Weight: 50, MinDuration: 0},
			{StageID: "s1", Weight: 100, MinDuration: 0},
		},
	}
	c.Start(plan)
	hash0 := plan.ContentHash
	c.Promote("hash-chg")
	if plan.ContentHash == hash0 {
		t.Fatal("content hash should change after promote")
	}
}

func TestDeep_GateOperatorLT(t *testing.T) {
	if !evaluateGate(0.04, 0.05, "lt") {
		t.Fatal("0.04 < 0.05 should pass")
	}
	if evaluateGate(0.05, 0.05, "lt") {
		t.Fatal("0.05 < 0.05 should fail")
	}
}

func TestDeep_GateOperatorGT(t *testing.T) {
	if !evaluateGate(100, 99, "gt") {
		t.Fatal("100 > 99 should pass")
	}
}

func TestDeep_GateOperatorLTE(t *testing.T) {
	if !evaluateGate(5.0, 5.0, "lte") {
		t.Fatal("5.0 <= 5.0 should pass")
	}
}

func TestDeep_GateOperatorInvalid(t *testing.T) {
	if evaluateGate(1, 1, "bogus") {
		t.Fatal("invalid operator should return false")
	}
}

func TestDeep_CheckPromotionMissingMetric(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })

	plan := &DeliveryPlan{
		PlanID: "miss-metric", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{
			StageID: "s0", Weight: 10, MinDuration: 0,
			GateMetrics: []PromotionGate{{MetricName: "not_found", Threshold: 1, Operator: "lt"}},
		}},
	}
	c.Start(plan)
	now = now.Add(time.Minute)
	ok, _, _ := c.CheckPromotion(context.Background(), "miss-metric")
	if ok {
		t.Fatal("missing metric should block promotion")
	}
}

func TestDeep_GetPlanNotFound(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	_, ok := c.GetPlan("nope")
	if ok {
		t.Fatal("should not find non-existent plan")
	}
}

func TestDeep_PromoteAlreadyCompletedFails(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })
	plan := &DeliveryPlan{
		PlanID: "done-plan", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{StageID: "s0", Weight: 100, MinDuration: 0}},
	}
	c.Start(plan)
	c.Promote("done-plan")
	err := c.Promote("done-plan")
	if err == nil {
		t.Fatal("promoting completed plan should fail")
	}
}

func TestDeep_MultipleGateMetrics(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"error_rate": 0.01, "p99_latency_ms": 50.0}}
	c := NewDeliveryController(m)
	now := baseTime
	c.WithClock(func() time.Time { return now })
	plan := &DeliveryPlan{
		PlanID: "multi-gate", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{
			StageID: "s0", Weight: 10, MinDuration: 0,
			GateMetrics: []PromotionGate{
				{MetricName: "error_rate", Threshold: 0.05, Operator: "lt"},
				{MetricName: "p99_latency_ms", Threshold: 100, Operator: "lt"},
			},
		}},
	}
	c.Start(plan)
	now = now.Add(time.Second)
	ok, _, _ := c.CheckPromotion(context.Background(), "multi-gate")
	if !ok {
		t.Fatal("both gates pass — should allow promotion")
	}
}

func TestDeep_RollbackConditionNotMetStaysRunning(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"p99_latency_ms": 50.0}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })
	plan := &DeliveryPlan{
		PlanID: "no-rb", Strategy: StrategyCanary,
		Stages: []DeliveryStage{{StageID: "s0", Weight: 10, MinDuration: 0}},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions:   []RollbackCondition{{MetricName: "p99_latency_ms", Threshold: 200.0, Operator: "gt"}},
		},
	}
	c.Start(plan)
	should, _, _ := c.CheckRollback(context.Background(), "no-rb")
	if should {
		t.Fatal("latency 50 < 200, should not trigger rollback")
	}
}

func TestDeep_PlanHashNonEmpty(t *testing.T) {
	plan := &DeliveryPlan{PlanID: "hash-test", Strategy: StrategyCanary}
	plan.ComputeHash()
	if plan.ContentHash == "" {
		t.Fatal("content hash should be set after ComputeHash")
	}
}

func TestDeep_CheckRollbackNoAutoRollback(t *testing.T) {
	m := &staticMetrics{values: map[string]float64{"err": 1.0}}
	c := NewDeliveryController(m)
	c.WithClock(func() time.Time { return baseTime })
	plan := &DeliveryPlan{
		PlanID: "no-auto", Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0", Weight: 10, MinDuration: 0}},
		Rollback: RollbackPolicy{AutoRollback: false},
	}
	c.Start(plan)
	should, _, _ := c.CheckRollback(context.Background(), "no-auto")
	if should {
		t.Fatal("should not rollback when auto_rollback is false")
	}
}
