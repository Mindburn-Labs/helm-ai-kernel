package simulation

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── 1-5: Scenario with 50 steps ────────────────────────────────

func TestDeep_Scenario50Steps(t *testing.T) {
	steps := make([]ScenarioStep, 50)
	for i := 0; i < 50; i++ {
		steps[i] = ScenarioStep{
			StepID:           fmt.Sprintf("step-%d", i),
			Action:           fmt.Sprintf("action-%d", i),
			Actor:            "agent-1",
			ExpectedDecision: "ALLOW",
		}
	}
	sc := NewScenario("sc-50", "50-step", "test", "security", steps)
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(sc.Steps) != 50 {
		t.Fatalf("want 50 steps got %d", len(sc.Steps))
	}
}

func TestDeep_ScenarioRunAllPass(t *testing.T) {
	twin := NewOrgTwin("twin-1", "t1", nil, nil, nil, nil)
	steps := make([]ScenarioStep, 50)
	for i := 0; i < 50; i++ {
		steps[i] = ScenarioStep{
			StepID: fmt.Sprintf("s%d", i), Action: "safe_action",
			Actor: "agent", ExpectedDecision: "ALLOW",
		}
	}
	sc := NewScenario("sc-pass", "pass", "desc", "compliance", steps)
	sc.Run(twin)
	if sc.Status != ScenarioStatusPassed {
		t.Fatalf("all matching expected decisions should pass, got %s", sc.Status)
	}
	if sc.PassRate() != 1.0 {
		t.Fatalf("pass rate should be 1.0 got %f", sc.PassRate())
	}
}

func TestDeep_ScenarioRunPartialFail(t *testing.T) {
	// OrgTwin with a deny policy
	policies := []PolicyRule{{ID: "p1", Name: "block", Expression: "deny", EffectTypes: []string{"dangerous"}, Enabled: true}}
	twin := NewOrgTwin("twin-2", "t1", policies, nil, nil, nil)
	steps := []ScenarioStep{
		{StepID: "s1", Action: "dangerous", Actor: "a", ExpectedDecision: "ALLOW"},
		{StepID: "s2", Action: "safe", Actor: "a", ExpectedDecision: "ALLOW"},
	}
	sc := NewScenario("sc-fail", "fail", "desc", "security", steps)
	sc.Run(twin)
	if sc.Status != ScenarioStatusFailed {
		t.Fatalf("mismatched expected should fail, got %s", sc.Status)
	}
	if sc.PassRate() >= 1.0 {
		t.Error("pass rate should be < 1.0")
	}
}

func TestDeep_ScenarioValidateEmptySteps(t *testing.T) {
	sc := NewScenario("sc-empty", "empty", "desc", "security", nil)
	if sc.Validate() == nil {
		t.Error("no steps must fail validation")
	}
}

func TestDeep_ScenarioValidateMissingAction(t *testing.T) {
	steps := []ScenarioStep{{StepID: "s1", Action: "", ExpectedDecision: "ALLOW"}}
	sc := NewScenario("sc-bad", "bad", "desc", "security", steps)
	if sc.Validate() == nil {
		t.Error("empty action must fail validation")
	}
}

// ── 6-10: Runner with 10 concurrent simulations ────────────────

func TestDeep_RunnerConcurrentBudgetSims(t *testing.T) {
	runner := NewRunner()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sim := BudgetSimulation{
				SimID:    fmt.Sprintf("sim-%d", i),
				BudgetID: "b1",
				Scenario: "GROWTH",
				Adjustments: []BudgetAdjustment{
					{Category: "compute", ChangeType: "INCREASE", AmountCents: int64(i * 1000)},
				},
				Duration: 30 * 24 * time.Hour,
			}
			_, err := runner.RunBudgetSim(sim)
			if err != nil {
				t.Errorf("sim-%d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	runs := runner.ListRuns()
	if len(runs) != 10 {
		t.Fatalf("want 10 runs got %d", len(runs))
	}
}

func TestDeep_RunnerConcurrentStaffingSims(t *testing.T) {
	runner := NewRunner()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			model := StaffingModel{
				ModelID: fmt.Sprintf("staff-%d", i),
				Workers: []StaffEntry{
					{ActorType: "AGENT", Role: "researcher", Count: 5, CostPerHour: 10, Utilization: 0.8, AvailableHours: 40},
				},
			}
			_, err := runner.RunStaffingSim(model)
			if err != nil {
				t.Errorf("staff-%d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestDeep_RunnerGetRun(t *testing.T) {
	runner := NewRunner()
	runner.RunBudgetSim(BudgetSimulation{
		SimID: "test-get", BudgetID: "b1", Scenario: "CONTRACTION",
		Duration: time.Hour,
	})
	run, err := runner.GetRun("test-get")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "COMPLETED" {
		t.Fatalf("run should be completed got %s", run.Status)
	}
}

func TestDeep_RunnerGetRunNotFound(t *testing.T) {
	runner := NewRunner()
	_, err := runner.GetRun("missing")
	if err == nil {
		t.Error("missing run should error")
	}
}

func TestDeep_RunnerEmptySimID(t *testing.T) {
	runner := NewRunner()
	_, err := runner.RunBudgetSim(BudgetSimulation{SimID: ""})
	if err == nil {
		t.Error("empty SimID must error")
	}
}

// ── 11-15: Budget simulation edge cases ─────────────────────────

func TestDeep_BudgetSimIncrease(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunBudgetSim(BudgetSimulation{
		SimID: "inc", BudgetID: "b1", Scenario: "GROWTH",
		Adjustments: []BudgetAdjustment{{ChangeType: "INCREASE", AmountCents: 500000}},
		Duration:    60 * 24 * time.Hour,
	})
	if !result.OverBudget {
		t.Error("positive projected spend should be over budget")
	}
}

func TestDeep_BudgetSimDecrease(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunBudgetSim(BudgetSimulation{
		SimID: "dec", BudgetID: "b1", Scenario: "CONTRACTION",
		Adjustments: []BudgetAdjustment{{ChangeType: "DECREASE", AmountCents: 100000}},
		Duration:    30 * 24 * time.Hour,
	})
	if result.OverBudget {
		t.Error("negative projected spend should not be over budget")
	}
}

func TestDeep_BudgetSimSet(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunBudgetSim(BudgetSimulation{
		SimID: "set", BudgetID: "b1", Scenario: "CUSTOM",
		Adjustments: []BudgetAdjustment{{ChangeType: "SET", AmountCents: 200000}},
		Duration:    30 * 24 * time.Hour,
	})
	if result.ProjectedSpendCents != 200000 {
		t.Fatalf("SET should set projected to 200000 got %d", result.ProjectedSpendCents)
	}
}

func TestDeep_BudgetSimRiskLevels(t *testing.T) {
	cases := []struct {
		amount int64
		risk   string
	}{
		{50000, "LOW"},
		{200000, "MEDIUM"},
		{600000, "HIGH"},
		{2000000, "CRITICAL"},
	}
	runner := NewRunner()
	for i, c := range cases {
		r, _ := runner.RunBudgetSim(BudgetSimulation{
			SimID:       fmt.Sprintf("risk-%d", i),
			Adjustments: []BudgetAdjustment{{ChangeType: "SET", AmountCents: c.amount}},
			Duration:    30 * 24 * time.Hour,
		})
		if r.RiskLevel != c.risk {
			t.Errorf("amount=%d: want %s got %s", c.amount, c.risk, r.RiskLevel)
		}
	}
}

func TestDeep_BudgetSimBurnRate(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunBudgetSim(BudgetSimulation{
		SimID:       "burn",
		Adjustments: []BudgetAdjustment{{ChangeType: "SET", AmountCents: 300000}},
		Duration:    90 * 24 * time.Hour, // ~3 months
	})
	if result.BurnRate <= 0 {
		t.Error("burn rate should be positive for positive spend")
	}
}

// ── 16-20: OrgTwin comparison with many deltas ──────────────────

func TestDeep_OrgTwinCompareAddedPolicies(t *testing.T) {
	base := NewOrgTwin("base", "t1", []PolicyRule{{ID: "p1"}}, nil, nil, nil)
	target := NewOrgTwin("target", "t1", []PolicyRule{{ID: "p1"}, {ID: "p2"}, {ID: "p3"}}, nil, nil, nil)
	delta := Compare(base, target)
	if len(delta.AddedPolicies) != 2 {
		t.Fatalf("want 2 added policies got %d", len(delta.AddedPolicies))
	}
}

func TestDeep_OrgTwinCompareRemovedPolicies(t *testing.T) {
	base := NewOrgTwin("base", "t1", []PolicyRule{{ID: "p1"}, {ID: "p2"}, {ID: "p3"}}, nil, nil, nil)
	target := NewOrgTwin("target", "t1", []PolicyRule{{ID: "p1"}}, nil, nil, nil)
	delta := Compare(base, target)
	if len(delta.RemovedPolicies) != 2 {
		t.Fatalf("want 2 removed policies got %d", len(delta.RemovedPolicies))
	}
}

func TestDeep_OrgTwinCompareAddedRoles(t *testing.T) {
	base := NewOrgTwin("base", "t1", nil, []RoleSnapshot{{RoleID: "r1"}}, nil, nil)
	target := NewOrgTwin("target", "t1", nil, []RoleSnapshot{{RoleID: "r1"}, {RoleID: "r2"}}, nil, nil)
	delta := Compare(base, target)
	if len(delta.AddedRoles) != 1 {
		t.Fatalf("want 1 added role got %d", len(delta.AddedRoles))
	}
}

func TestDeep_OrgTwinCompareRemovedRoles(t *testing.T) {
	base := NewOrgTwin("base", "t1", nil, []RoleSnapshot{{RoleID: "r1"}, {RoleID: "r2"}}, nil, nil)
	target := NewOrgTwin("target", "t1", nil, nil, nil, nil)
	delta := Compare(base, target)
	if len(delta.RemovedRoles) != 2 {
		t.Fatalf("want 2 removed roles got %d", len(delta.RemovedRoles))
	}
}

func TestDeep_OrgTwinCompareManyDeltas(t *testing.T) {
	var basePolicies []PolicyRule
	for i := 0; i < 50; i++ {
		basePolicies = append(basePolicies, PolicyRule{ID: fmt.Sprintf("p%d", i)})
	}
	var targetPolicies []PolicyRule
	for i := 25; i < 75; i++ {
		targetPolicies = append(targetPolicies, PolicyRule{ID: fmt.Sprintf("p%d", i)})
	}
	base := NewOrgTwin("base", "t1", basePolicies, nil, nil, nil)
	target := NewOrgTwin("target", "t1", targetPolicies, nil, nil, nil)
	delta := Compare(base, target)
	if len(delta.AddedPolicies) != 25 {
		t.Fatalf("want 25 added got %d", len(delta.AddedPolicies))
	}
	if len(delta.RemovedPolicies) != 25 {
		t.Fatalf("want 25 removed got %d", len(delta.RemovedPolicies))
	}
}

// ── 21-25: More edge cases ──────────────────────────────────────

func TestDeep_OrgTwinContentHash(t *testing.T) {
	twin := NewOrgTwin("tw1", "t1", nil, nil, nil, nil)
	if twin.ContentHash == "" {
		t.Error("content hash should be computed")
	}
}

func TestDeep_SimulateDecisionDeny(t *testing.T) {
	policies := []PolicyRule{{ID: "p1", Enabled: true, EffectTypes: []string{"DELETE"}}}
	twin := NewOrgTwin("tw1", "t1", policies, nil, nil, nil)
	result := SimulateDecision(twin, "DELETE", "agent")
	if result.Decision != "DENY" {
		t.Fatalf("DELETE should be denied got %s", result.Decision)
	}
	if result.ContentHash == "" {
		t.Error("simulation result should have content hash")
	}
}

func TestDeep_SimulateDecisionAllow(t *testing.T) {
	twin := NewOrgTwin("tw1", "t1", nil, nil, nil, nil)
	result := SimulateDecision(twin, "READ", "agent")
	if result.Decision != "ALLOW" {
		t.Fatalf("no matching policies should allow, got %s", result.Decision)
	}
}

func TestDeep_ScenarioPassRateZero(t *testing.T) {
	sc := NewScenario("sc-0", "empty", "desc", "security", nil)
	if sc.PassRate() != 0 {
		t.Error("no steps = 0 pass rate")
	}
}

func TestDeep_StaffingSimHeadcount(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunStaffingSim(StaffingModel{
		ModelID: "hc-test",
		Workers: []StaffEntry{
			{ActorType: "HUMAN", Role: "ops", Count: 3, CostPerHour: 50, Utilization: 0.9, AvailableHours: 40},
			{ActorType: "AGENT", Role: "research", Count: 10, CostPerHour: 5, Utilization: 1.0, AvailableHours: 168},
		},
	})
	if result.HeadcountByType["HUMAN"] != 3 {
		t.Fatalf("want 3 humans got %d", result.HeadcountByType["HUMAN"])
	}
	if result.HeadcountByType["AGENT"] != 10 {
		t.Fatalf("want 10 agents got %d", result.HeadcountByType["AGENT"])
	}
	if result.TotalWeeklyCost <= 0 {
		t.Error("weekly cost should be positive")
	}
}
