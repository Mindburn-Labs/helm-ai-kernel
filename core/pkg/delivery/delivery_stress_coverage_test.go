package delivery

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

var deliveryClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

type stressMetrics struct {
	values map[string]float64
}

func (m *stressMetrics) GetMetric(_ context.Context, name string) (float64, error) {
	v, ok := m.values[name]
	if !ok {
		return 0, fmt.Errorf("metric %s not found", name)
	}
	return v, nil
}

func make10StagePlan(id string) *DeliveryPlan {
	stages := make([]DeliveryStage, 10)
	for i := range stages {
		stages[i] = DeliveryStage{
			StageID:     fmt.Sprintf("s%d", i),
			Weight:      (i + 1) * 10,
			MinDuration: 0,
			GateMetrics: []PromotionGate{
				{MetricName: "error_rate", Threshold: 0.05, Operator: "lt"},
			},
		}
	}
	return &DeliveryPlan{PlanID: id, Strategy: StrategyCanary, Stages: stages}
}

// --- 10-Stage Canary ---

func TestStress_Delivery_10StageCanary(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := make10StagePlan("canary-10")
	if err := ctrl.Start(plan); err != nil {
		t.Fatal(err)
	}
	if plan.Status != DeliveryInProgress {
		t.Fatalf("expected IN_PROGRESS, got %s", plan.Status)
	}
}

func TestStress_Delivery_PromoteAllStages(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := make10StagePlan("promote-all")
	ctrl.Start(plan)
	for i := 0; i < 10; i++ {
		if err := ctrl.Promote("promote-all"); err != nil {
			t.Fatalf("promote stage %d: %v", i, err)
		}
	}
	if plan.Status != DeliveryPromoted {
		t.Fatalf("expected PROMOTED, got %s", plan.Status)
	}
}

func TestStress_Delivery_RollbackFromStage0(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("rb-0")
	ctrl.Start(plan)
	if err := ctrl.Rollback("rb-0", "bad metrics"); err != nil {
		t.Fatal(err)
	}
	if plan.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", plan.Status)
	}
}

func TestStress_Delivery_RollbackFromStage1(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("rb-1")
	ctrl.Start(plan)
	ctrl.Promote("rb-1")
	ctrl.Rollback("rb-1", "revert")
	if plan.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", plan.Status)
	}
}

func TestStress_Delivery_RollbackFromStage5(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("rb-5")
	ctrl.Start(plan)
	for i := 0; i < 5; i++ {
		ctrl.Promote("rb-5")
	}
	ctrl.Rollback("rb-5", "midway revert")
	if plan.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", plan.Status)
	}
}

func TestStress_Delivery_RollbackFromStage9(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("rb-9")
	ctrl.Start(plan)
	for i := 0; i < 9; i++ {
		ctrl.Promote("rb-9")
	}
	ctrl.Rollback("rb-9", "last stage revert")
	if plan.Status != DeliveryRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", plan.Status)
	}
}

func TestStress_Delivery_RollbackEachStage(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	for stage := 0; stage < 10; stage++ {
		ctrl := NewDeliveryController(metrics)
		plan := make10StagePlan(fmt.Sprintf("rb-each-%d", stage))
		ctrl.Start(plan)
		for i := 0; i < stage; i++ {
			ctrl.Promote(plan.PlanID)
		}
		ctrl.Rollback(plan.PlanID, "rollback")
		if plan.Status != DeliveryRolledBack {
			t.Fatalf("stage %d: expected ROLLED_BACK", stage)
		}
	}
}

// --- SLO Gate with 10 Metrics ---

func TestStress_Delivery_SLOGate10Metrics(t *testing.T) {
	values := make(map[string]float64)
	gates := make([]PromotionGate, 10)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("metric_%d", i)
		values[name] = 0.01
		gates[i] = PromotionGate{MetricName: name, Threshold: 0.05, Operator: "lt"}
	}
	metrics := &stressMetrics{values: values}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := &DeliveryPlan{
		PlanID:   "slo-10",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0", GateMetrics: gates}},
	}
	ctrl.Start(plan)
	can, reason, err := ctrl.CheckPromotion(context.Background(), "slo-10")
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Fatalf("expected promotion allowed: %s", reason)
	}
}

func TestStress_Delivery_SLOGateOneFails(t *testing.T) {
	values := make(map[string]float64)
	gates := make([]PromotionGate, 10)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("metric_%d", i)
		values[name] = 0.01
		gates[i] = PromotionGate{MetricName: name, Threshold: 0.05, Operator: "lt"}
	}
	values["metric_7"] = 0.10 // fails threshold
	metrics := &stressMetrics{values: values}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := &DeliveryPlan{
		PlanID:   "slo-fail",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0", GateMetrics: gates}},
	}
	ctrl.Start(plan)
	can, _, _ := ctrl.CheckPromotion(context.Background(), "slo-fail")
	if can {
		t.Fatal("expected promotion blocked when one metric fails")
	}
}

func TestStress_Delivery_SLOGateMissingMetric(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{
		PlanID:   "slo-miss",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0", GateMetrics: []PromotionGate{{MetricName: "absent", Threshold: 0.05, Operator: "lt"}}}},
	}
	ctrl.Start(plan)
	can, _, _ := ctrl.CheckPromotion(context.Background(), "slo-miss")
	if can {
		t.Fatal("expected promotion blocked for missing metric")
	}
}

func TestStress_Delivery_CheckPromotionSoakTime(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	metrics := &stressMetrics{values: map[string]float64{"err": 0.01}}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(func() time.Time { return now })
	plan := &DeliveryPlan{
		PlanID:   "soak",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0", MinDuration: time.Hour, GateMetrics: []PromotionGate{{MetricName: "err", Threshold: 0.05, Operator: "lt"}}}},
	}
	ctrl.Start(plan)
	can, _, _ := ctrl.CheckPromotion(context.Background(), "soak")
	if can {
		t.Fatal("expected blocked by soak time")
	}
}

func TestStress_Delivery_CheckPromotionNotFound(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	_, _, err := ctrl.CheckPromotion(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected error for unknown plan")
	}
}

func TestStress_Delivery_PromoteNotFound(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	if err := ctrl.Promote("ghost"); err == nil {
		t.Fatal("expected error for unknown plan")
	}
}

func TestStress_Delivery_RollbackNotFound(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	if err := ctrl.Rollback("ghost", "reason"); err == nil {
		t.Fatal("expected error for unknown plan")
	}
}

func TestStress_Delivery_EmptyStagesRejected(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{PlanID: "empty", Stages: []DeliveryStage{}}
	if err := ctrl.Start(plan); err == nil {
		t.Fatal("expected error for empty stages")
	}
}

func TestStress_Delivery_ContentHashUpdated(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"err": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("hash-update")
	ctrl.Start(plan)
	h1 := plan.ContentHash
	ctrl.Promote("hash-update")
	if plan.ContentHash == h1 {
		t.Fatal("content hash should change after promote")
	}
}

func TestStress_Delivery_GetPlan(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("get-plan")
	ctrl.Start(plan)
	got, ok := ctrl.GetPlan("get-plan")
	if !ok || got.PlanID != "get-plan" {
		t.Fatal("expected to get plan")
	}
}

func TestStress_Delivery_GetPlanNotFound(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	_, ok := ctrl.GetPlan("ghost")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestStress_Delivery_CheckRollbackCondition(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.20}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{
		PlanID:   "auto-rb",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0"}},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions:   []RollbackCondition{{MetricName: "error_rate", Threshold: 0.10, Operator: "gt"}},
		},
	}
	ctrl.Start(plan)
	should, _, _ := ctrl.CheckRollback(context.Background(), "auto-rb")
	if !should {
		t.Fatal("expected auto-rollback triggered")
	}
}

func TestStress_Delivery_CheckRollbackNotTriggered(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{
		PlanID:   "no-rb",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0"}},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions:   []RollbackCondition{{MetricName: "error_rate", Threshold: 0.10, Operator: "gt"}},
		},
	}
	ctrl.Start(plan)
	should, _, _ := ctrl.CheckRollback(context.Background(), "no-rb")
	if should {
		t.Fatal("expected no rollback")
	}
}

func TestStress_Delivery_EvaluateGateOperators(t *testing.T) {
	tests := []struct {
		op          string
		val, thresh float64
		want        bool
	}{
		{"lt", 0.01, 0.05, true}, {"lt", 0.05, 0.05, false},
		{"gt", 0.10, 0.05, true}, {"gt", 0.05, 0.05, false},
		{"lte", 0.05, 0.05, true}, {"lte", 0.06, 0.05, false},
		{"gte", 0.05, 0.05, true}, {"gte", 0.04, 0.05, false},
		{"invalid", 0.01, 0.05, false},
	}
	for _, tt := range tests {
		got := evaluateGate(tt.val, tt.thresh, tt.op)
		if got != tt.want {
			t.Errorf("evaluateGate(%f, %f, %s) = %v, want %v", tt.val, tt.thresh, tt.op, got, tt.want)
		}
	}
}

// --- Concurrent Promote/Rollback ---

func TestStress_Concurrent_PromoteAndRollback_20Goroutines(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	for i := 0; i < 20; i++ {
		plan := make10StagePlan(fmt.Sprintf("conc-%d", i))
		ctrl.Start(plan)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctrl.Promote(fmt.Sprintf("conc-%d", id))
		}(i)
	}
	for i := 10; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctrl.Rollback(fmt.Sprintf("conc-%d", id), "concurrent")
		}(i)
	}
	wg.Wait()
}

func TestStress_Delivery_PromoteAlreadyCompleted(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"error_rate": 0.01}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{
		PlanID:   "done",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0"}},
	}
	ctrl.Start(plan)
	ctrl.Promote("done")
	if err := ctrl.Promote("done"); err == nil {
		t.Fatal("expected error promoting completed plan")
	}
}

func TestStress_Delivery_ComputeHash(t *testing.T) {
	plan := make10StagePlan("hash-test")
	plan.ComputeHash()
	if plan.ContentHash == "" {
		t.Fatal("expected content hash to be set")
	}
}

func TestStress_Delivery_StrategyCanary(t *testing.T) {
	plan := make10StagePlan("strat-canary")
	if plan.Strategy != StrategyCanary {
		t.Fatalf("expected CANARY, got %s", plan.Strategy)
	}
}

func TestStress_Delivery_StrategyShadow(t *testing.T) {
	plan := &DeliveryPlan{PlanID: "shadow", Strategy: StrategyShadow, Stages: []DeliveryStage{{StageID: "s0"}}}
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	ctrl.Start(plan)
	if plan.Status != DeliveryInProgress {
		t.Fatal("expected in progress")
	}
}

func TestStress_Delivery_StrategyBlueGreen(t *testing.T) {
	plan := &DeliveryPlan{PlanID: "bg", Strategy: StrategyBlueGreen, Stages: []DeliveryStage{{StageID: "s0"}}}
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	ctrl.Start(plan)
	if plan.Strategy != StrategyBlueGreen {
		t.Fatal("strategy should be BLUE_GREEN")
	}
}

func TestStress_Delivery_StageWeight10(t *testing.T) {
	plan := make10StagePlan("weight")
	if plan.Stages[0].Weight != 10 {
		t.Fatalf("expected first stage weight 10, got %d", plan.Stages[0].Weight)
	}
	if plan.Stages[9].Weight != 100 {
		t.Fatalf("expected last stage weight 100, got %d", plan.Stages[9].Weight)
	}
}

func TestStress_Delivery_PromoteOnlyWhenInProgress(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{PlanID: "not-started", Stages: []DeliveryStage{{StageID: "s0"}}}
	plan.Status = DeliveryPending
	ctrl.mu.Lock()
	ctrl.plans["not-started"] = plan
	ctrl.mu.Unlock()
	if err := ctrl.Promote("not-started"); err == nil {
		t.Fatal("expected error promoting a pending plan")
	}
}

func TestStress_Delivery_CheckPromotionOnCompleted(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{PlanID: "completed", Strategy: StrategyCanary, Stages: []DeliveryStage{{StageID: "s0"}}}
	ctrl.Start(plan)
	ctrl.Promote("completed")
	_, _, err := ctrl.CheckPromotion(context.Background(), "completed")
	if err == nil {
		t.Fatal("expected error checking promotion on completed plan")
	}
}

func TestStress_Delivery_RollbackAutoDisabled(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{"err": 1.0}}
	ctrl := NewDeliveryController(metrics)
	plan := &DeliveryPlan{
		PlanID:   "no-auto",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{{StageID: "s0"}},
		Rollback: RollbackPolicy{AutoRollback: false},
	}
	ctrl.Start(plan)
	should, _, _ := ctrl.CheckRollback(context.Background(), "no-auto")
	if should {
		t.Fatal("expected no rollback when auto disabled")
	}
}

func TestStress_Delivery_ContentHashDeterminism(t *testing.T) {
	p1 := make10StagePlan("det-1")
	p1.ComputeHash()
	p2 := make10StagePlan("det-1")
	p2.ComputeHash()
	if p1.ContentHash != p2.ContentHash {
		t.Fatal("content hash should be deterministic for same plan")
	}
}

func TestStress_Delivery_StartSetsTime(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := make10StagePlan("time-set")
	ctrl.Start(plan)
	if plan.StartedAt.IsZero() {
		t.Fatal("expected start time to be set")
	}
}

func TestStress_Delivery_StartSetsFirstStage(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("first-stage")
	ctrl.Start(plan)
	if plan.Stages[0].Status != DeliveryInProgress {
		t.Fatalf("expected first stage IN_PROGRESS, got %s", plan.Stages[0].Status)
	}
}

func TestStress_Delivery_PromoteCompleteSetsTime(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := &DeliveryPlan{PlanID: "comp-time", Strategy: StrategyCanary, Stages: []DeliveryStage{{StageID: "s0"}}}
	ctrl.Start(plan)
	ctrl.Promote("comp-time")
	if plan.CompletedAt.IsZero() {
		t.Fatal("expected completed time to be set")
	}
}

func TestStress_Delivery_SLOGateAllOperators(t *testing.T) {
	ops := []struct {
		op          string
		val, thresh float64
		want        bool
	}{
		{"lt", 1, 2, true}, {"gt", 3, 2, true}, {"lte", 2, 2, true}, {"gte", 2, 2, true},
	}
	for _, o := range ops {
		values := map[string]float64{"m": o.val}
		metrics := &stressMetrics{values: values}
		ctrl := NewDeliveryController(metrics)
		ctrl.WithClock(deliveryClock)
		plan := &DeliveryPlan{
			PlanID:   fmt.Sprintf("op-%s", o.op),
			Strategy: StrategyCanary,
			Stages:   []DeliveryStage{{StageID: "s0", GateMetrics: []PromotionGate{{MetricName: "m", Threshold: o.thresh, Operator: o.op}}}},
		}
		ctrl.Start(plan)
		can, _, _ := ctrl.CheckPromotion(context.Background(), plan.PlanID)
		if can != o.want {
			t.Errorf("operator %s: expected %v, got %v", o.op, o.want, can)
		}
	}
}

func TestStress_Concurrent_Start20Plans(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			plan := make10StagePlan(fmt.Sprintf("par-%d", id))
			ctrl.Start(plan)
		}(i)
	}
	wg.Wait()
}

func TestStress_Delivery_RollbackSetsTime(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	ctrl.WithClock(deliveryClock)
	plan := make10StagePlan("rb-time")
	ctrl.Start(plan)
	ctrl.Rollback("rb-time", "reason")
	if plan.CompletedAt.IsZero() {
		t.Fatal("expected completed time set on rollback")
	}
}

func TestStress_Delivery_CheckRollbackNotFound(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	should, _, _ := ctrl.CheckRollback(context.Background(), "ghost")
	if should {
		t.Fatal("expected no rollback for nonexistent plan")
	}
}

func TestStress_Delivery_CurrentStageAdvances(t *testing.T) {
	metrics := &stressMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	plan := make10StagePlan("cs-adv")
	ctrl.Start(plan)
	ctrl.Promote("cs-adv")
	if plan.CurrentStage != 1 {
		t.Fatalf("expected current stage 1, got %d", plan.CurrentStage)
	}
}
