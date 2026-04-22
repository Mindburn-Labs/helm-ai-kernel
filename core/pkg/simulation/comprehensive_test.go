package simulation

import (
	"strings"
	"testing"
	"time"
)

// ── Scenario creation ───────────────────────────────────────────

func TestNewScenarioSetsID(t *testing.T) {
	s := NewScenario("sc-1", "n", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.ID != "sc-1" {
		t.Fatalf("got ID %q, want %q", s.ID, "sc-1")
	}
}

func TestNewScenarioSetsName(t *testing.T) {
	s := NewScenario("sc-1", "my-name", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.Name != "my-name" {
		t.Fatalf("got Name %q, want %q", s.Name, "my-name")
	}
}

func TestNewScenarioSetsDescription(t *testing.T) {
	s := NewScenario("sc-1", "n", "desc-text", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.Description != "desc-text" {
		t.Fatalf("got Description %q", s.Description)
	}
}

func TestNewScenarioSetsCategory(t *testing.T) {
	s := NewScenario("sc-1", "n", "d", "compliance", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.Category != "compliance" {
		t.Fatalf("got Category %q", s.Category)
	}
}

func TestNewScenarioInitialStatusIsDraft(t *testing.T) {
	s := NewScenario("sc-1", "n", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.Status != ScenarioStatusDraft {
		t.Fatalf("got Status %q, want DRAFT", s.Status)
	}
}

func TestNewScenarioSetsCreatedAt(t *testing.T) {
	before := time.Now().UTC()
	s := NewScenario("sc-1", "n", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.CreatedAt.Before(before) {
		t.Fatal("CreatedAt should not be before function call")
	}
}

func TestNewScenarioPreservesSteps(t *testing.T) {
	steps := []ScenarioStep{{StepID: "1", Action: "X", ExpectedDecision: "ALLOW"}, {StepID: "2", Action: "Y", ExpectedDecision: "DENY"}}
	s := NewScenario("sc-1", "n", "d", "security", steps)
	if len(s.Steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(s.Steps))
	}
}

func TestNewScenarioResultsNil(t *testing.T) {
	s := NewScenario("sc-1", "n", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.Results != nil {
		t.Fatal("Results should be nil before Run")
	}
}

// ── ScenarioStep fields ─────────────────────────────────────────

func TestScenarioStepAction(t *testing.T) {
	step := ScenarioStep{Action: "EXEC_SHELL"}
	if step.Action != "EXEC_SHELL" {
		t.Fatalf("got Action %q", step.Action)
	}
}

func TestScenarioStepActor(t *testing.T) {
	step := ScenarioStep{Actor: "agent-7"}
	if step.Actor != "agent-7" {
		t.Fatalf("got Actor %q", step.Actor)
	}
}

func TestScenarioStepExpectedDecision(t *testing.T) {
	step := ScenarioStep{ExpectedDecision: "ESCALATE"}
	if step.ExpectedDecision != "ESCALATE" {
		t.Fatalf("got ExpectedDecision %q", step.ExpectedDecision)
	}
}

func TestScenarioStepContextMap(t *testing.T) {
	step := ScenarioStep{Context: map[string]string{"env": "prod"}}
	if step.Context["env"] != "prod" {
		t.Fatalf("got context env=%q", step.Context["env"])
	}
}

// ── ScenarioAssertion fields ────────────────────────────────────

func TestScenarioAssertionField(t *testing.T) {
	a := ScenarioAssertion{Field: "result.decision"}
	if a.Field != "result.decision" {
		t.Fatalf("got Field %q", a.Field)
	}
}

func TestScenarioAssertionOperator(t *testing.T) {
	a := ScenarioAssertion{Operator: "eq"}
	if a.Operator != "eq" {
		t.Fatalf("got Operator %q", a.Operator)
	}
}

func TestScenarioAssertionValue(t *testing.T) {
	a := ScenarioAssertion{Value: "DENY"}
	if a.Value != "DENY" {
		t.Fatalf("got Value %q", a.Value)
	}
}

func TestScenarioAssertionContainsOperator(t *testing.T) {
	a := ScenarioAssertion{Operator: "contains", Value: "shell"}
	if a.Operator != "contains" {
		t.Fatalf("got Operator %q", a.Operator)
	}
}

// ── Scenario.Status constants ───────────────────────────────────

func TestScenarioStatusDraftValue(t *testing.T) {
	if ScenarioStatusDraft != "DRAFT" {
		t.Fatalf("got %q", ScenarioStatusDraft)
	}
}

func TestScenarioStatusReadyValue(t *testing.T) {
	if ScenarioStatusReady != "READY" {
		t.Fatalf("got %q", ScenarioStatusReady)
	}
}

func TestScenarioStatusRunningValue(t *testing.T) {
	if ScenarioStatusRunning != "RUNNING" {
		t.Fatalf("got %q", ScenarioStatusRunning)
	}
}

func TestScenarioStatusPassedValue(t *testing.T) {
	if ScenarioStatusPassed != "PASSED" {
		t.Fatalf("got %q", ScenarioStatusPassed)
	}
}

func TestScenarioStatusFailedValue(t *testing.T) {
	if ScenarioStatusFailed != "FAILED" {
		t.Fatalf("got %q", ScenarioStatusFailed)
	}
}

// ── Scenario.Validate ───────────────────────────────────────────

func TestValidateRejectsEmptyID(t *testing.T) {
	s := &Scenario{Name: "n", Steps: []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "id") {
		t.Fatalf("expected id error, got %v", err)
	}
}

func TestValidateRejectsEmptyName(t *testing.T) {
	s := &Scenario{ID: "s-1", Steps: []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("expected name error, got %v", err)
	}
}

func TestValidateRejectsNoSteps(t *testing.T) {
	s := &Scenario{ID: "s-1", Name: "n"}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "step") {
		t.Fatalf("expected step error, got %v", err)
	}
}

func TestValidateRejectsEmptyStepAction(t *testing.T) {
	s := &Scenario{ID: "s-1", Name: "n", Steps: []ScenarioStep{{ExpectedDecision: "ALLOW"}}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("expected action error, got %v", err)
	}
}

func TestValidateRejectsEmptyExpectedDecision(t *testing.T) {
	s := &Scenario{ID: "s-1", Name: "n", Steps: []ScenarioStep{{Action: "a"}}}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "expected_decision") {
		t.Fatalf("expected expected_decision error, got %v", err)
	}
}

func TestValidateAcceptsValidScenario(t *testing.T) {
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if err := s.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ── Scenario.PassRate ───────────────────────────────────────────

func TestPassRateZeroWithoutResults(t *testing.T) {
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{{Action: "a", ExpectedDecision: "ALLOW"}})
	if s.PassRate() != 0 {
		t.Fatalf("got %f, want 0", s.PassRate())
	}
}

func TestPassRateZeroWithNoSteps(t *testing.T) {
	s := &Scenario{}
	if s.PassRate() != 0 {
		t.Fatalf("got %f, want 0", s.PassRate())
	}
}

func TestPassRateFullOnAllMatch(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{
		{StepID: "1", Action: "FS_READ", Actor: "a", ExpectedDecision: "ALLOW"},
	})
	s.Run(twin)
	if s.PassRate() != 1.0 {
		t.Fatalf("got %f, want 1.0", s.PassRate())
	}
}

func TestPassRatePartialMatch(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{
		{StepID: "1", Action: "FS_READ", Actor: "a", ExpectedDecision: "ALLOW"},
		{StepID: "2", Action: "FS_READ", Actor: "a", ExpectedDecision: "DENY"},
	})
	s.Run(twin)
	if s.PassRate() != 0.5 {
		t.Fatalf("got %f, want 0.5", s.PassRate())
	}
}

// ── Scenario.Run status transitions ─────────────────────────────

func TestRunTransitionsDraftToRunningToPassed(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{
		{StepID: "1", Action: "FS_READ", Actor: "a", ExpectedDecision: "ALLOW"},
	})
	if s.Status != ScenarioStatusDraft {
		t.Fatalf("pre-run status %q, want DRAFT", s.Status)
	}
	s.Run(twin)
	if s.Status != ScenarioStatusPassed {
		t.Fatalf("post-run status %q, want PASSED", s.Status)
	}
}

func TestRunTransitionsDraftToFailed(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{
		{StepID: "1", Action: "FS_READ", Actor: "a", ExpectedDecision: "DENY"},
	})
	s.Run(twin)
	if s.Status != ScenarioStatusFailed {
		t.Fatalf("got status %q, want FAILED", s.Status)
	}
}

func TestRunPopulatesResults(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{
		{StepID: "1", Action: "X", Actor: "a", ExpectedDecision: "ALLOW"},
		{StepID: "2", Action: "Y", Actor: "a", ExpectedDecision: "ALLOW"},
	})
	s.Run(twin)
	if len(s.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(s.Results))
	}
}

func TestRunWithPolicyDenyMatchExpectsPass(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", []PolicyRule{
		{ID: "p-1", EffectTypes: []string{"NET_OUT"}, Enabled: true},
	}, nil, nil, nil)
	s := NewScenario("s-1", "n", "d", "security", []ScenarioStep{
		{StepID: "1", Action: "NET_OUT", Actor: "a", ExpectedDecision: "DENY"},
	})
	s.Run(twin)
	if s.Status != ScenarioStatusPassed {
		t.Fatalf("got %q, want PASSED", s.Status)
	}
}

// ── NewRunner ───────────────────────────────────────────────────

func TestNewRunnerNotNil(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
}

func TestNewRunnerEmptyRuns(t *testing.T) {
	r := NewRunner()
	if len(r.ListRuns()) != 0 {
		t.Fatalf("new runner should have 0 runs, got %d", len(r.ListRuns()))
	}
}

// ── Runner.RunBudgetSim ─────────────────────────────────────────

func TestRunBudgetSimRequiresSimID(t *testing.T) {
	r := NewRunner()
	_, err := r.RunBudgetSim(BudgetSimulation{})
	if err == nil {
		t.Fatal("expected error for empty sim_id")
	}
}

func TestRunBudgetSimIncrease(t *testing.T) {
	r := NewRunner()
	res, err := r.RunBudgetSim(BudgetSimulation{
		SimID:    "b-1",
		Duration: 30 * 24 * time.Hour,
		Adjustments: []BudgetAdjustment{
			{ChangeType: "INCREASE", AmountCents: 50000},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ProjectedSpendCents != 50000 {
		t.Fatalf("got projected %d, want 50000", res.ProjectedSpendCents)
	}
}

func TestRunBudgetSimDecrease(t *testing.T) {
	r := NewRunner()
	res, err := r.RunBudgetSim(BudgetSimulation{
		SimID:    "b-2",
		Duration: 30 * 24 * time.Hour,
		Adjustments: []BudgetAdjustment{
			{ChangeType: "INCREASE", AmountCents: 100000},
			{ChangeType: "DECREASE", AmountCents: 40000},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ProjectedSpendCents != 60000 {
		t.Fatalf("got projected %d, want 60000", res.ProjectedSpendCents)
	}
}

func TestRunBudgetSimSetOverrides(t *testing.T) {
	r := NewRunner()
	res, err := r.RunBudgetSim(BudgetSimulation{
		SimID:    "b-3",
		Duration: 30 * 24 * time.Hour,
		Adjustments: []BudgetAdjustment{
			{ChangeType: "INCREASE", AmountCents: 999999},
			{ChangeType: "SET", AmountCents: 42},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ProjectedSpendCents != 42 {
		t.Fatalf("got projected %d, want 42", res.ProjectedSpendCents)
	}
}

func TestRunBudgetSimOverBudgetFlag(t *testing.T) {
	r := NewRunner()
	res, _ := r.RunBudgetSim(BudgetSimulation{
		SimID:       "b-4",
		Duration:    30 * 24 * time.Hour,
		Adjustments: []BudgetAdjustment{{ChangeType: "INCREASE", AmountCents: 1}},
	})
	if !res.OverBudget {
		t.Fatal("expected OverBudget true for positive spend")
	}
}

func TestRunBudgetSimRiskLevelLow(t *testing.T) {
	r := NewRunner()
	res, _ := r.RunBudgetSim(BudgetSimulation{
		SimID:       "b-5",
		Duration:    30 * 24 * time.Hour,
		Adjustments: []BudgetAdjustment{{ChangeType: "INCREASE", AmountCents: 500}},
	})
	if res.RiskLevel != "LOW" {
		t.Fatalf("got risk %q, want LOW", res.RiskLevel)
	}
}

func TestRunBudgetSimRiskLevelCritical(t *testing.T) {
	r := NewRunner()
	res, _ := r.RunBudgetSim(BudgetSimulation{
		SimID:       "b-6",
		Duration:    30 * 24 * time.Hour,
		Adjustments: []BudgetAdjustment{{ChangeType: "INCREASE", AmountCents: 2_000_000}},
	})
	if res.RiskLevel != "CRITICAL" {
		t.Fatalf("got risk %q, want CRITICAL", res.RiskLevel)
	}
}

func TestRunBudgetSimTracksRun(t *testing.T) {
	r := NewRunner()
	r.RunBudgetSim(BudgetSimulation{SimID: "b-7", Duration: time.Hour})
	run, err := r.GetRun("b-7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.SimType != "BUDGET" {
		t.Fatalf("got SimType %q, want BUDGET", run.SimType)
	}
}

func TestRunBudgetSimCompletesRun(t *testing.T) {
	r := NewRunner()
	r.RunBudgetSim(BudgetSimulation{SimID: "b-8", Duration: time.Hour})
	run, _ := r.GetRun("b-8")
	if run.Status != "COMPLETED" {
		t.Fatalf("got status %q, want COMPLETED", run.Status)
	}
}

// ── Runner.RunStaffingSim ───────────────────────────────────────

func TestRunStaffingSimRequiresModelID(t *testing.T) {
	r := NewRunner()
	_, err := r.RunStaffingSim(StaffingModel{})
	if err == nil {
		t.Fatal("expected error for empty model_id")
	}
}

func TestRunStaffingSimComputesCost(t *testing.T) {
	r := NewRunner()
	res, err := r.RunStaffingSim(StaffingModel{
		ModelID: "m-1",
		Workers: []StaffEntry{
			{ActorType: "HUMAN", CostPerHour: 50, AvailableHours: 40, Count: 2, Utilization: 1.0},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.TotalWeeklyCost != 4000 {
		t.Fatalf("got cost %f, want 4000", res.TotalWeeklyCost)
	}
}

func TestRunStaffingSimComputesCapacity(t *testing.T) {
	r := NewRunner()
	res, _ := r.RunStaffingSim(StaffingModel{
		ModelID: "m-2",
		Workers: []StaffEntry{
			{ActorType: "AGENT", CostPerHour: 10, AvailableHours: 168, Count: 1, Utilization: 0.5},
		},
	})
	if res.TotalCapacityHrs != 84 {
		t.Fatalf("got capacity %f, want 84", res.TotalCapacityHrs)
	}
}

func TestRunStaffingSimHeadcountByType(t *testing.T) {
	r := NewRunner()
	res, _ := r.RunStaffingSim(StaffingModel{
		ModelID: "m-3",
		Workers: []StaffEntry{
			{ActorType: "HUMAN", Count: 3, CostPerHour: 1, AvailableHours: 1, Utilization: 1},
			{ActorType: "AGENT", Count: 5, CostPerHour: 1, AvailableHours: 1, Utilization: 1},
		},
	})
	if res.HeadcountByType["HUMAN"] != 3 || res.HeadcountByType["AGENT"] != 5 {
		t.Fatalf("got headcount %v", res.HeadcountByType)
	}
}

func TestRunStaffingSimTracksRun(t *testing.T) {
	r := NewRunner()
	r.RunStaffingSim(StaffingModel{ModelID: "m-4", Workers: []StaffEntry{}})
	run, err := r.GetRun("m-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.SimType != "STAFFING" {
		t.Fatalf("got SimType %q, want STAFFING", run.SimType)
	}
}

// ── Runner.ListRuns / GetRun ────────────────────────────────────

func TestListRunsAfterMultiple(t *testing.T) {
	r := NewRunner()
	r.RunBudgetSim(BudgetSimulation{SimID: "x1", Duration: time.Hour})
	r.RunBudgetSim(BudgetSimulation{SimID: "x2", Duration: time.Hour})
	if len(r.ListRuns()) != 2 {
		t.Fatalf("got %d runs, want 2", len(r.ListRuns()))
	}
}

func TestGetRunNotFound(t *testing.T) {
	r := NewRunner()
	_, err := r.GetRun("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing run")
	}
}

// ── SimRun type and status ──────────────────────────────────────

func TestSimRunBudgetType(t *testing.T) {
	r := NewRunner()
	r.RunBudgetSim(BudgetSimulation{SimID: "tr-1", Duration: time.Hour})
	run, _ := r.GetRun("tr-1")
	if run.SimType != "BUDGET" {
		t.Fatalf("got %q, want BUDGET", run.SimType)
	}
}

func TestSimRunStaffingType(t *testing.T) {
	r := NewRunner()
	r.RunStaffingSim(StaffingModel{ModelID: "tr-2", Workers: []StaffEntry{}})
	run, _ := r.GetRun("tr-2")
	if run.SimType != "STAFFING" {
		t.Fatalf("got %q, want STAFFING", run.SimType)
	}
}

func TestSimRunHasEndedAt(t *testing.T) {
	r := NewRunner()
	r.RunBudgetSim(BudgetSimulation{SimID: "tr-3", Duration: time.Hour})
	run, _ := r.GetRun("tr-3")
	if run.EndedAt == nil {
		t.Fatal("EndedAt should be set after completion")
	}
}

func TestSimRunStartedAtBeforeEndedAt(t *testing.T) {
	r := NewRunner()
	r.RunBudgetSim(BudgetSimulation{SimID: "tr-4", Duration: time.Hour})
	run, _ := r.GetRun("tr-4")
	if run.EndedAt.Before(run.StartedAt) {
		t.Fatal("EndedAt should not be before StartedAt")
	}
}

// ── SimulateDecision ────────────────────────────────────────────

func TestSimulateDecisionAllowNoPolicy(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	res := SimulateDecision(twin, "READ", "a")
	if res.Decision != "ALLOW" {
		t.Fatalf("got %q, want ALLOW", res.Decision)
	}
}

func TestSimulateDecisionDenyMatchingPolicy(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", []PolicyRule{
		{ID: "p-1", EffectTypes: []string{"WRITE"}, Enabled: true},
	}, nil, nil, nil)
	res := SimulateDecision(twin, "WRITE", "a")
	if res.Decision != "DENY" {
		t.Fatalf("got %q, want DENY", res.Decision)
	}
}

func TestSimulateDecisionDisabledPolicyIgnored(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", []PolicyRule{
		{ID: "p-1", EffectTypes: []string{"WRITE"}, Enabled: false},
	}, nil, nil, nil)
	res := SimulateDecision(twin, "WRITE", "a")
	if res.Decision != "ALLOW" {
		t.Fatalf("got %q, want ALLOW (disabled policy)", res.Decision)
	}
}

func TestSimulateDecisionWildcardDenies(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", []PolicyRule{
		{ID: "p-1", EffectTypes: []string{"*"}, Enabled: true},
	}, nil, nil, nil)
	res := SimulateDecision(twin, "ANYTHING", "a")
	if res.Decision != "DENY" {
		t.Fatalf("got %q, want DENY for wildcard", res.Decision)
	}
}

func TestSimulateDecisionTriggeredByPopulated(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", []PolicyRule{
		{ID: "p-99", EffectTypes: []string{"X"}, Enabled: true},
	}, nil, nil, nil)
	res := SimulateDecision(twin, "X", "a")
	if len(res.TriggeredBy) != 1 || res.TriggeredBy[0] != "p-99" {
		t.Fatalf("got TriggeredBy %v", res.TriggeredBy)
	}
}

func TestSimulateDecisionRiskScoreIncreases(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", []PolicyRule{
		{ID: "p-1", EffectTypes: []string{"X"}, Enabled: true},
		{ID: "p-2", EffectTypes: []string{"X"}, Enabled: true},
	}, nil, nil, nil)
	res := SimulateDecision(twin, "X", "a")
	if res.RiskScore < 0.5 {
		t.Fatalf("expected risk >= 0.5 for 2 triggers, got %f", res.RiskScore)
	}
}

func TestSimulateDecisionContentHashNonEmpty(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	res := SimulateDecision(twin, "READ", "a")
	if !strings.HasPrefix(res.ContentHash, "sha256:") {
		t.Fatalf("got hash %q, want sha256: prefix", res.ContentHash)
	}
}

func TestSimulateDecisionDurationPositive(t *testing.T) {
	twin := NewOrgTwin("tw-1", "t-1", nil, nil, nil, nil)
	res := SimulateDecision(twin, "READ", "a")
	if res.Duration < 0 {
		t.Fatalf("got negative duration %v", res.Duration)
	}
}

// ── Budget risk classification ──────────────────────────────────

func TestClassifyBudgetRiskMedium(t *testing.T) {
	if classifyBudgetRisk(200_000) != "MEDIUM" {
		t.Fatalf("got %q, want MEDIUM", classifyBudgetRisk(200_000))
	}
}

func TestClassifyBudgetRiskHigh(t *testing.T) {
	if classifyBudgetRisk(750_000) != "HIGH" {
		t.Fatalf("got %q, want HIGH", classifyBudgetRisk(750_000))
	}
}

// ── StressTest type fields ──────────────────────────────────────

func TestStressScenarioTypeLoad(t *testing.T) {
	s := StressScenario{Type: "LOAD", Intensity: 5}
	if s.Type != "LOAD" || s.Intensity != 5 {
		t.Fatalf("got Type=%q Intensity=%d", s.Type, s.Intensity)
	}
}

func TestStressTestRunnerFields(t *testing.T) {
	r := StressTestRunner{TestID: "st-1", Concurrency: 10, DurationSecs: 60}
	if r.Concurrency != 10 || r.DurationSecs != 60 {
		t.Fatalf("got Concurrency=%d DurationSecs=%d", r.Concurrency, r.DurationSecs)
	}
}

// ── countByType helper ──────────────────────────────────────────

func TestCountByTypeAggregates(t *testing.T) {
	workers := []StaffEntry{
		{ActorType: "HUMAN", Count: 2},
		{ActorType: "HUMAN", Count: 3},
		{ActorType: "ROBOT", Count: 1},
	}
	counts := countByType(workers)
	if counts["HUMAN"] != 5 || counts["ROBOT"] != 1 {
		t.Fatalf("got %v", counts)
	}
}

func TestCountByTypeEmpty(t *testing.T) {
	counts := countByType(nil)
	if len(counts) != 0 {
		t.Fatalf("expected empty map, got %v", counts)
	}
}
