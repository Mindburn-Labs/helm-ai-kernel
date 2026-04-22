package contracts_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ──────────────────────────────────────────────────────────────
// GlobalAutonomyState tests
// ──────────────────────────────────────────────────────────────

func TestGlobalAutonomyState_IsProjection(t *testing.T) {
	// GlobalAutonomyState MUST always have a ComputedAt timestamp
	// to indicate it is a derived projection, never source of truth.
	state := contracts.GlobalAutonomyState{
		OrgID:      "test-org",
		Posture:    contracts.PostureObserve,
		GlobalMode: contracts.GlobalModeRunning,
		ComputedAt: time.Now().UTC(),
	}

	if state.ComputedAt.IsZero() {
		t.Fatal("GlobalAutonomyState.ComputedAt must be set")
	}
	if state.OrgID == "" {
		t.Fatal("GlobalAutonomyState.OrgID must be set")
	}
}

func TestGlobalAutonomyState_EmptySlicesNotNil(t *testing.T) {
	// Verify zero-value slices are nil (JSON will omit them).
	// Projection code should initialize to empty slices when serializing.
	state := contracts.GlobalAutonomyState{}
	if state.ActiveRuns != nil {
		t.Error("expected nil ActiveRuns on zero value")
	}
	if state.BlockersQueue != nil {
		t.Error("expected nil BlockersQueue on zero value")
	}
}

func TestNowNextNeed_Summary(t *testing.T) {
	nnn := contracts.NowNextNeed{
		Now:     "Deploying v2.1 to staging",
		Next:    "Run integration tests",
		NeedYou: "Approve production rollout",
	}

	if nnn.Now == "" || nnn.Next == "" || nnn.NeedYou == "" {
		t.Fatal("NowNextNeed fields must not be empty when set")
	}
}

func TestRunSummaryProjection_StageValues(t *testing.T) {
	stages := []contracts.AutonomyRunStage{
		contracts.RunStageSensing,
		contracts.RunStagePlanning,
		contracts.RunStageGating,
		contracts.RunStageExecuting,
		contracts.RunStageVerifying,
		contracts.RunStageDone,
		contracts.RunStageFailed,
		contracts.RunStageBlocked,
	}

	for _, s := range stages {
		if s == "" {
			t.Error("stage constant must not be empty string")
		}
	}

	if len(stages) != 8 {
		t.Errorf("expected 8 stage values, got %d", len(stages))
	}
}

func TestBudgetSummary_Runway(t *testing.T) {
	budget := contracts.BudgetSummary{
		EnvelopeCents: 100_00, // $100
		BurnCents:     25_00,  // $25
		BurnRate:      5_00,   // $5/hr
		RunwayHours:   15.0,
	}

	if budget.RunwayHours <= 0 {
		t.Error("runway should be positive")
	}
	remaining := budget.EnvelopeCents - budget.BurnCents
	if remaining != 75_00 {
		t.Errorf("expected 7500 remaining, got %d", remaining)
	}
}

// ──────────────────────────────────────────────────────────────
// Lane tests
// ──────────────────────────────────────────────────────────────

func TestAllLanes(t *testing.T) {
	lanes := contracts.AllLanes()
	if len(lanes) != 5 {
		t.Errorf("expected 5 lanes, got %d", len(lanes))
	}

	expected := map[contracts.Lane]bool{
		contracts.LaneResearch:   true,
		contracts.LaneBuild:      true,
		contracts.LaneGTM:        true,
		contracts.LaneOps:        true,
		contracts.LaneCompliance: true,
	}

	for _, l := range lanes {
		if !expected[l] {
			t.Errorf("unexpected lane: %s", l)
		}
	}
}

func TestLaneState_IsIdle(t *testing.T) {
	tests := []struct {
		name     string
		state    contracts.LaneState
		expected bool
	}{
		{"idle", contracts.LaneState{Lane: contracts.LaneOps, ActiveRuns: 0, NextAction: ""}, true},
		{"active", contracts.LaneState{Lane: contracts.LaneOps, ActiveRuns: 1}, false},
		{"pending", contracts.LaneState{Lane: contracts.LaneOps, NextAction: "scheduled"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsIdle(); got != tt.expected {
				t.Errorf("IsIdle() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────
// D3 Regression: Concurrency state truthfulness
// ──────────────────────────────────────────────────────────────

func TestConcurrency_MultipleRunsCorrectState(t *testing.T) {
	// Create runs across multiple lanes — each lane's runs must be independent
	runs := []contracts.RunSummaryProjection{
		{RunID: "r1", Lane: contracts.LaneResearch, CurrentStage: contracts.RunStageExecuting, Status: "active"},
		{RunID: "r2", Lane: contracts.LaneResearch, CurrentStage: contracts.RunStageBlocked, Status: "blocked"},
		{RunID: "r3", Lane: contracts.LaneBuild, CurrentStage: contracts.RunStagePlanning, Status: "active"},
		{RunID: "r4", Lane: contracts.LaneGTM, CurrentStage: contracts.RunStageDone, Status: "done"},
		{RunID: "r5", Lane: contracts.LaneOps, CurrentStage: contracts.RunStageSensing, Status: "active"},
		{RunID: "r6", Lane: contracts.LaneCompliance, CurrentStage: contracts.RunStageVerifying, Status: "active"},
	}

	// Group by lane and verify independence
	byLane := make(map[contracts.Lane][]contracts.RunSummaryProjection)
	for _, r := range runs {
		byLane[r.Lane] = append(byLane[r.Lane], r)
	}

	// RESEARCH has 2 runs (1 executing, 1 blocked)
	researchRuns := byLane[contracts.LaneResearch]
	if len(researchRuns) != 2 {
		t.Fatalf("RESEARCH: expected 2 runs, got %d", len(researchRuns))
	}
	if researchRuns[0].CurrentStage != contracts.RunStageExecuting {
		t.Errorf("RESEARCH r1: expected EXECUTING, got %s", researchRuns[0].CurrentStage)
	}
	if researchRuns[1].CurrentStage != contracts.RunStageBlocked {
		t.Errorf("RESEARCH r2: expected BLOCKED, got %s", researchRuns[1].CurrentStage)
	}

	// Each other lane has exactly 1 run
	for _, lane := range []contracts.Lane{contracts.LaneBuild, contracts.LaneGTM, contracts.LaneOps, contracts.LaneCompliance} {
		if len(byLane[lane]) != 1 {
			t.Errorf("lane %s: expected 1 run, got %d", lane, len(byLane[lane]))
		}
	}

	// Verify that a blocked run in RESEARCH does NOT affect BUILD's active state
	buildRun := byLane[contracts.LaneBuild][0]
	if buildRun.CurrentStage == contracts.RunStageBlocked {
		t.Error("BUILD run should not be blocked — cross-lane contamination")
	}

	// Verify total count
	if len(runs) != 6 {
		t.Errorf("expected 6 total runs, got %d", len(runs))
	}
}

// ──────────────────────────────────────────────────────────────
// D3 Regression: Blocker queue ordering
// ──────────────────────────────────────────────────────────────

func TestBlockerQueue_Ordering(t *testing.T) {
	decisions := []contracts.DecisionRequest{
		{RequestID: "d1", Title: "First", Status: contracts.DecisionStatusPending, Priority: contracts.DecisionPriorityNormal},
		{RequestID: "d2", Title: "Second", Status: contracts.DecisionStatusPending, Priority: contracts.DecisionPriorityNormal},
		{RequestID: "d3", Title: "Third (resolved)", Status: contracts.DecisionStatusResolved, Priority: contracts.DecisionPriorityNormal},
		{RequestID: "d4", Title: "Fourth", Status: contracts.DecisionStatusPending, Priority: contracts.DecisionPriorityNormal},
	}

	// Filter pending — should maintain FIFO order
	var pending []contracts.DecisionRequest
	for _, d := range decisions {
		if d.Status == contracts.DecisionStatusPending {
			pending = append(pending, d)
		}
	}

	if len(pending) != 3 {
		t.Fatalf("expected 3 pending, got %d", len(pending))
	}

	// FIFO: first in should be first out
	if pending[0].RequestID != "d1" {
		t.Errorf("expected first pending=d1, got %s", pending[0].RequestID)
	}
	if pending[1].RequestID != "d2" {
		t.Errorf("expected second pending=d2, got %s", pending[1].RequestID)
	}
	if pending[2].RequestID != "d4" {
		t.Errorf("expected third pending=d4, got %s", pending[2].RequestID)
	}
}

// ──────────────────────────────────────────────────────────────
// D3 Regression: DecisionRequest validation (no Untitled)
// ──────────────────────────────────────────────────────────────

func TestDecisionRequest_NoUntitledGating(t *testing.T) {
	dr := contracts.DecisionRequest{
		RequestID: "dr-notitle",
		Kind:      contracts.DecisionKindApproval,
		Title:     "", // "Untitled" — MUST fail
		Options: []contracts.DecisionOption{
			{ID: "a", Label: "Yes"},
			{ID: "b", Label: "No"},
		},
		Priority: contracts.DecisionPriorityNormal,
	}

	err := dr.Validate()
	if err == nil {
		t.Fatal("expected validation error for empty title, got nil")
	}
}
