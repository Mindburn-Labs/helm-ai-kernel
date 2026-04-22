package delivery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

type mockMetrics struct {
	values map[string]float64
}

func (m *mockMetrics) GetMetric(_ context.Context, name string) (float64, error) {
	v, ok := m.values[name]
	if !ok {
		return 0, fmt.Errorf("metric not found: %s", name)
	}
	return v, nil
}

func newTestPlan() *DeliveryPlan {
	return &DeliveryPlan{
		PlanID:   "plan-001",
		Strategy: StrategyCanary,
		Stages: []DeliveryStage{
			{
				StageID:     "stage-1",
				Weight:      10,
				MinDuration: 5 * time.Minute,
				AutoPromote: true,
				GateMetrics: []PromotionGate{
					{MetricName: "error_rate", Threshold: 0.01, Operator: "lt"},
					{MetricName: "success_rate", Threshold: 0.99, Operator: "gte"},
				},
			},
			{
				StageID:     "stage-2",
				Weight:      50,
				MinDuration: 10 * time.Minute,
				AutoPromote: false,
				GateMetrics: []PromotionGate{
					{MetricName: "error_rate", Threshold: 0.01, Operator: "lt"},
				},
			},
			{
				StageID:     "stage-3",
				Weight:      100,
				MinDuration: 0,
				AutoPromote: true,
			},
		},
		Rollback: RollbackPolicy{
			AutoRollback: true,
			Conditions: []RollbackCondition{
				{MetricName: "error_rate", Threshold: 0.05, Operator: "gt"},
			},
		},
	}
}

func TestDeliveryController_Start(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if plan.Status != DeliveryInProgress {
		t.Errorf("expected status IN_PROGRESS, got %s", plan.Status)
	}
	if plan.CurrentStage != 0 {
		t.Errorf("expected current stage 0, got %d", plan.CurrentStage)
	}
	if plan.Stages[0].Status != DeliveryInProgress {
		t.Errorf("expected first stage IN_PROGRESS, got %s", plan.Stages[0].Status)
	}
	if plan.StartedAt != now {
		t.Errorf("expected started_at %v, got %v", now, plan.StartedAt)
	}
	if plan.Stages[0].EnteredAt != now {
		t.Errorf("expected stage entered_at %v, got %v", now, plan.Stages[0].EnteredAt)
	}

	// Verify plan is retrievable
	got, ok := ctrl.GetPlan("plan-001")
	if !ok {
		t.Fatal("expected plan to be retrievable")
	}
	if got.PlanID != "plan-001" {
		t.Errorf("expected plan_id plan-001, got %s", got.PlanID)
	}
}

func TestDeliveryController_Promote(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Promote stage 1 → stage 2
	if err := ctrl.Promote("plan-001"); err != nil {
		t.Fatalf("Promote stage 1 failed: %v", err)
	}
	if plan.CurrentStage != 1 {
		t.Errorf("expected current stage 1, got %d", plan.CurrentStage)
	}
	if plan.Stages[0].Status != DeliveryPromoted {
		t.Errorf("expected stage 0 PROMOTED, got %s", plan.Stages[0].Status)
	}
	if plan.Stages[1].Status != DeliveryInProgress {
		t.Errorf("expected stage 1 IN_PROGRESS, got %s", plan.Stages[1].Status)
	}
	if plan.Status != DeliveryInProgress {
		t.Errorf("expected plan still IN_PROGRESS, got %s", plan.Status)
	}

	// Promote stage 2 → stage 3
	if err := ctrl.Promote("plan-001"); err != nil {
		t.Fatalf("Promote stage 2 failed: %v", err)
	}
	if plan.CurrentStage != 2 {
		t.Errorf("expected current stage 2, got %d", plan.CurrentStage)
	}

	// Promote stage 3 (final) — completes delivery
	if err := ctrl.Promote("plan-001"); err != nil {
		t.Fatalf("Promote final stage failed: %v", err)
	}
	if plan.Status != DeliveryPromoted {
		t.Errorf("expected plan PROMOTED, got %s", plan.Status)
	}
	if plan.CompletedAt != now {
		t.Errorf("expected completed_at %v, got %v", now, plan.CompletedAt)
	}
}

func TestDeliveryController_Rollback(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := ctrl.Rollback("plan-001", "error rate spike"); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if plan.Status != DeliveryRolledBack {
		t.Errorf("expected status ROLLED_BACK, got %s", plan.Status)
	}
	if plan.CompletedAt != now {
		t.Errorf("expected completed_at %v, got %v", now, plan.CompletedAt)
	}
}

func TestDeliveryController_CheckPromotion_SoakTime(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{
		"error_rate":   0.001,
		"success_rate": 0.999,
	}}
	ctrl := NewDeliveryController(metrics)
	start := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	current := start
	ctrl.WithClock(func() time.Time { return current })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Only 2 minutes elapsed (soak is 5 min) — should fail
	current = start.Add(2 * time.Minute)
	canPromote, reason, err := ctrl.CheckPromotion(context.Background(), "plan-001")
	if err != nil {
		t.Fatalf("CheckPromotion returned error: %v", err)
	}
	if canPromote {
		t.Error("expected promotion blocked by soak time")
	}
	if !strings.Contains(reason, "soak time remaining") {
		t.Errorf("expected soak time reason, got: %s", reason)
	}
}

func TestDeliveryController_CheckPromotion_GatePass(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{
		"error_rate":   0.005, // below 0.01 threshold (lt)
		"success_rate": 0.995, // above 0.99 threshold (gte)
	}}
	ctrl := NewDeliveryController(metrics)
	start := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	current := start
	ctrl.WithClock(func() time.Time { return current })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Advance past soak time
	current = start.Add(10 * time.Minute)
	canPromote, reason, err := ctrl.CheckPromotion(context.Background(), "plan-001")
	if err != nil {
		t.Fatalf("CheckPromotion returned error: %v", err)
	}
	if !canPromote {
		t.Errorf("expected promotion to pass, reason: %s", reason)
	}
	if reason != "all gates passed" {
		t.Errorf("expected 'all gates passed', got: %s", reason)
	}
}

func TestDeliveryController_CheckPromotion_GateFail(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{
		"error_rate":   0.02,  // above 0.01 threshold — gate should fail
		"success_rate": 0.995, // passes
	}}
	ctrl := NewDeliveryController(metrics)
	start := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	current := start
	ctrl.WithClock(func() time.Time { return current })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Advance past soak time
	current = start.Add(10 * time.Minute)
	canPromote, reason, err := ctrl.CheckPromotion(context.Background(), "plan-001")
	if err != nil {
		t.Fatalf("CheckPromotion returned error: %v", err)
	}
	if canPromote {
		t.Error("expected promotion to be blocked by gate failure")
	}
	if !strings.Contains(reason, "gate error_rate failed") {
		t.Errorf("expected gate failure reason, got: %s", reason)
	}
}

func TestDeliveryController_CheckRollback(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{
		"error_rate": 0.10, // above 0.05 threshold (gt) — should trigger rollback
	}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	shouldRollback, reason, err := ctrl.CheckRollback(context.Background(), "plan-001")
	if err != nil {
		t.Fatalf("CheckRollback returned error: %v", err)
	}
	if !shouldRollback {
		t.Error("expected rollback to be triggered")
	}
	if !strings.Contains(reason, "rollback condition met") {
		t.Errorf("expected rollback reason, got: %s", reason)
	}
}

func TestDeliveryController_CheckRollback_NoTrigger(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{
		"error_rate": 0.01, // below 0.05 threshold — should not trigger
	}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	shouldRollback, _, err := ctrl.CheckRollback(context.Background(), "plan-001")
	if err != nil {
		t.Fatalf("CheckRollback returned error: %v", err)
	}
	if shouldRollback {
		t.Error("expected rollback NOT to be triggered")
	}
}

func TestDeliveryController_EmptyStages(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)

	plan := &DeliveryPlan{
		PlanID:   "plan-empty",
		Strategy: StrategyCanary,
		Stages:   []DeliveryStage{},
	}

	err := ctrl.Start(plan)
	if err == nil {
		t.Fatal("expected error for empty stages")
	}
	if !strings.Contains(err.Error(), "no stages") {
		t.Errorf("expected 'no stages' error, got: %v", err)
	}
}

func TestDeliveryController_ContentHash(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Hash should be set after Start
	hash1 := plan.ContentHash
	if hash1 == "" {
		t.Fatal("expected content hash to be set after Start")
	}
	if !strings.HasPrefix(hash1, "sha256:") {
		t.Errorf("expected sha256: prefix, got: %s", hash1)
	}

	// Hash should change after Promote
	if err := ctrl.Promote("plan-001"); err != nil {
		t.Fatalf("Promote failed: %v", err)
	}
	hash2 := plan.ContentHash
	if hash2 == "" {
		t.Fatal("expected content hash after Promote")
	}
	if hash2 == hash1 {
		t.Error("expected content hash to change after Promote")
	}

	// Hash should change after Rollback
	if err := ctrl.Rollback("plan-001", "test"); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	hash3 := plan.ContentHash
	if hash3 == "" {
		t.Fatal("expected content hash after Rollback")
	}
	if hash3 == hash2 {
		t.Error("expected content hash to change after Rollback")
	}
}

func TestDeliveryController_PromoteNotFound(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)

	err := ctrl.Promote("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent plan")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestDeliveryController_RollbackNotFound(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)

	err := ctrl.Rollback("nonexistent", "reason")
	if err == nil {
		t.Fatal("expected error for nonexistent plan")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestDeliveryController_CheckPromotionNotInProgress(t *testing.T) {
	metrics := &mockMetrics{values: map[string]float64{}}
	ctrl := NewDeliveryController(metrics)
	now := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ctrl.WithClock(func() time.Time { return now })

	plan := newTestPlan()
	plan.Stages = plan.Stages[:1] // single stage
	if err := ctrl.Start(plan); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Complete the delivery
	if err := ctrl.Promote("plan-001"); err != nil {
		t.Fatalf("Promote failed: %v", err)
	}

	// Check promotion on completed plan
	_, _, err := ctrl.CheckPromotion(context.Background(), "plan-001")
	if err == nil {
		t.Fatal("expected error for non-in-progress plan")
	}
	if !strings.Contains(err.Error(), "not in progress") {
		t.Errorf("expected 'not in progress' error, got: %v", err)
	}
}
