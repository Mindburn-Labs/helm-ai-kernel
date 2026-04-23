package contracts_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────
// Reflex evaluator tests
// ──────────────────────────────────────────────────────────────

func TestEvaluateReflexes_NilState(t *testing.T) {
	actions := contracts.EvaluateReflexes(nil, contracts.DefaultReflexThresholds())
	if actions != nil {
		t.Errorf("expected nil actions for nil state, got %d", len(actions))
	}
}

func TestEvaluateReflexes_CriticalRisk_Freeze(t *testing.T) {
	state := &contracts.GlobalAutonomyState{
		RiskLevel: contracts.RiskLevelCritical,
	}
	actions := contracts.EvaluateReflexes(state, contracts.DefaultReflexThresholds())

	found := false
	for _, a := range actions {
		if a.Kind == contracts.ReflexFreeze && a.TargetGlobalMode == contracts.GlobalModeFrozen {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FREEZE action for CRITICAL risk level")
	}
}

func TestEvaluateReflexes_BudgetExhausted_Freeze(t *testing.T) {
	state := &contracts.GlobalAutonomyState{
		Budget: contracts.BudgetSummary{
			EnvelopeCents: 10000,
			BurnCents:     10000, // fully exhausted
		},
	}
	actions := contracts.EvaluateReflexes(state, contracts.DefaultReflexThresholds())

	found := false
	for _, a := range actions {
		if a.Kind == contracts.ReflexFreeze && a.Trigger.Condition == "Budget exhausted" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected FREEZE action for exhausted budget")
	}
}

func TestEvaluateReflexes_AnomalyCount_Island(t *testing.T) {
	anomalies := make([]contracts.Anomaly, 5)
	for i := range anomalies {
		anomalies[i] = contracts.Anomaly{ID: "a" + string(rune('0'+i)), Type: "test"}
	}

	state := &contracts.GlobalAutonomyState{
		Anomalies: anomalies,
	}
	actions := contracts.EvaluateReflexes(state, contracts.DefaultReflexThresholds())

	found := false
	for _, a := range actions {
		if a.Kind == contracts.ReflexIsland && a.TargetGlobalMode == contracts.GlobalModeIslanded {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ISLAND action for 5 anomalies (threshold=5)")
	}
}

func TestEvaluateReflexes_BlockedRuns_VelocityCap(t *testing.T) {
	runs := []contracts.RunSummaryProjection{
		{RunID: "r1", CurrentStage: contracts.RunStageBlocked},
		{RunID: "r2", CurrentStage: contracts.RunStageBlocked},
		{RunID: "r3", CurrentStage: contracts.RunStageBlocked},
		{RunID: "r4", CurrentStage: contracts.RunStageExecuting}, // not blocked
	}

	state := &contracts.GlobalAutonomyState{
		ActiveRuns: runs,
	}
	actions := contracts.EvaluateReflexes(state, contracts.DefaultReflexThresholds())

	found := false
	for _, a := range actions {
		if a.Kind == contracts.ReflexVelocityCap {
			found = true
			if a.Trigger.Metric != 3 {
				t.Errorf("expected metric=3 blocked runs, got %f", a.Trigger.Metric)
			}
			break
		}
	}
	if !found {
		t.Error("expected VELOCITY_CAP action for 3 blocked runs (threshold=3)")
	}
}

func TestEvaluateReflexes_FailedRun_Rollback(t *testing.T) {
	runs := []contracts.RunSummaryProjection{
		{RunID: "r-ok", CurrentStage: contracts.RunStageDone},
		{RunID: "r-fail", CurrentStage: contracts.RunStageFailed},
	}

	state := &contracts.GlobalAutonomyState{
		ActiveRuns: runs,
	}
	actions := contracts.EvaluateReflexes(state, contracts.DefaultReflexThresholds())

	found := false
	for _, a := range actions {
		if a.Kind == contracts.ReflexRollback && a.TargetRunID == "r-fail" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ROLLBACK action targeting r-fail")
	}
}

func TestEvaluateReflexes_Deterministic(t *testing.T) {
	state := &contracts.GlobalAutonomyState{
		RiskLevel: contracts.RiskLevelCritical,
		Anomalies: make([]contracts.Anomaly, 6),
		ActiveRuns: []contracts.RunSummaryProjection{
			{RunID: "r1", CurrentStage: contracts.RunStageBlocked},
			{RunID: "r2", CurrentStage: contracts.RunStageBlocked},
			{RunID: "r3", CurrentStage: contracts.RunStageBlocked},
			{RunID: "r4", CurrentStage: contracts.RunStageFailed},
		},
	}

	thresholds := contracts.DefaultReflexThresholds()

	// Run twice — must produce identical results
	a1 := contracts.EvaluateReflexes(state, thresholds)
	a2 := contracts.EvaluateReflexes(state, thresholds)

	if len(a1) != len(a2) {
		t.Fatalf("determinism: got %d actions first time, %d second time", len(a1), len(a2))
	}
	for i := range a1 {
		if a1[i].Kind != a2[i].Kind {
			t.Errorf("determinism: action[%d] kind %s vs %s", i, a1[i].Kind, a2[i].Kind)
		}
		if a1[i].Description != a2[i].Description {
			t.Errorf("determinism: action[%d] description mismatch", i)
		}
	}
}

func TestEvaluateReflexes_DisabledThresholds(t *testing.T) {
	state := &contracts.GlobalAutonomyState{
		RiskLevel: contracts.RiskLevelCritical,
		Anomalies: make([]contracts.Anomaly, 10),
		ActiveRuns: []contracts.RunSummaryProjection{
			{RunID: "r1", CurrentStage: contracts.RunStageBlocked},
			{RunID: "r2", CurrentStage: contracts.RunStageFailed},
		},
	}

	// All thresholds disabled
	thresholds := contracts.ReflexThresholds{}
	actions := contracts.EvaluateReflexes(state, thresholds)

	if len(actions) != 0 {
		t.Errorf("expected 0 actions with all thresholds disabled, got %d", len(actions))
	}
}

func TestAllReflexKinds(t *testing.T) {
	kinds := contracts.AllReflexKinds()
	if len(kinds) != 5 {
		t.Errorf("expected 5 reflex kinds, got %d", len(kinds))
	}

	seen := make(map[contracts.ReflexKind]bool)
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate reflex kind: %s", k)
		}
		seen[k] = true
	}
}

func TestReflexReceipt_Fields(t *testing.T) {
	receipt := contracts.ReflexReceipt{
		ID: "rx-001",
		Action: contracts.ReflexAction{
			Kind:        contracts.ReflexFreeze,
			Description: "test freeze",
		},
		Applied: true,
		OrgID:   "org-1",
	}

	if receipt.ID == "" {
		t.Error("receipt ID must not be empty")
	}
	if !receipt.Applied {
		t.Error("expected applied=true")
	}
	if receipt.SuppressedReason != "" {
		t.Error("expected no suppressed reason when applied")
	}
}
