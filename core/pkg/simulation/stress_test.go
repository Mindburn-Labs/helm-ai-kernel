package simulation

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
// 100 step scenario
// ────────────────────────────────────────────────────────────────────────

func TestStress_100StepScenario(t *testing.T) {
	steps := make([]ScenarioStep, 100)
	for i := 0; i < 100; i++ {
		steps[i] = ScenarioStep{StepID: fmt.Sprintf("step-%d", i), Action: "EXECUTE_TOOL", Actor: "agent", ExpectedDecision: "ALLOW"}
	}
	s := NewScenario("s1", "big-scenario", "100 steps", "security", steps)
	twin := NewOrgTwin("twin-1", "tenant-1", nil, nil, nil, nil)
	s.Run(twin)
	if len(s.Results) != 100 {
		t.Fatalf("expected 100 results, got %d", len(s.Results))
	}
}

func TestStress_100StepScenarioAllDeny(t *testing.T) {
	policy := PolicyRule{ID: "p1", Name: "deny-all", Expression: "deny", EffectTypes: []string{"*"}, Enabled: true}
	steps := make([]ScenarioStep, 100)
	for i := 0; i < 100; i++ {
		steps[i] = ScenarioStep{StepID: fmt.Sprintf("s-%d", i), Action: "WRITE", Actor: "a", ExpectedDecision: "DENY"}
	}
	s := NewScenario("s2", "deny-all", "all denied", "compliance", steps)
	twin := NewOrgTwin("t1", "ten-1", []PolicyRule{policy}, nil, nil, nil)
	s.Run(twin)
	if s.Status != ScenarioStatusPassed {
		t.Fatalf("expected PASSED, got %s", s.Status)
	}
}

func TestStress_ScenarioPassRate(t *testing.T) {
	steps := []ScenarioStep{
		{StepID: "s1", Action: "READ", Actor: "a", ExpectedDecision: "ALLOW"},
		{StepID: "s2", Action: "READ", Actor: "a", ExpectedDecision: "ALLOW"},
	}
	s := NewScenario("s3", "pass-rate", "test", "perf", steps)
	twin := NewOrgTwin("t1", "ten-1", nil, nil, nil, nil)
	s.Run(twin)
	pr := s.PassRate()
	if pr < 0 || pr > 1 {
		t.Fatalf("pass rate out of range: %f", pr)
	}
}

func TestStress_ScenarioPassRateNoResults(t *testing.T) {
	s := NewScenario("s4", "empty", "no results", "perf", []ScenarioStep{{StepID: "s", Action: "a", Actor: "a", ExpectedDecision: "ALLOW"}})
	if s.PassRate() != 0 {
		t.Fatal("expected 0 pass rate with no results")
	}
}

func TestStress_ScenarioValidateNoID(t *testing.T) {
	s := &Scenario{Name: "n", Steps: []ScenarioStep{{Action: "a", ExpectedDecision: "d"}}}
	if s.Validate() == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestStress_ScenarioValidateNoName(t *testing.T) {
	s := &Scenario{ID: "id", Steps: []ScenarioStep{{Action: "a", ExpectedDecision: "d"}}}
	if s.Validate() == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestStress_ScenarioValidateNoSteps(t *testing.T) {
	s := &Scenario{ID: "id", Name: "n", Steps: nil}
	if s.Validate() == nil {
		t.Fatal("expected error for no steps")
	}
}

func TestStress_ScenarioValidateEmptyAction(t *testing.T) {
	s := &Scenario{ID: "id", Name: "n", Steps: []ScenarioStep{{Action: "", ExpectedDecision: "d"}}}
	if s.Validate() == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestStress_ScenarioValidateEmptyDecision(t *testing.T) {
	s := &Scenario{ID: "id", Name: "n", Steps: []ScenarioStep{{Action: "a", ExpectedDecision: ""}}}
	if s.Validate() == nil {
		t.Fatal("expected error for empty expected decision")
	}
}

// ────────────────────────────────────────────────────────────────────────
// 50 concurrent simulations
// ────────────────────────────────────────────────────────────────────────

func TestStress_50ConcurrentSimulations(t *testing.T) {
	twin := NewOrgTwin("t1", "ten-1", nil, nil, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			result := SimulateDecision(twin, fmt.Sprintf("action-%d", n), "agent")
			if result == nil {
				t.Errorf("simulation %d returned nil", n)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_50ConcurrentScenarioRuns(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			steps := []ScenarioStep{{StepID: "s", Action: "READ", Actor: "a", ExpectedDecision: "ALLOW"}}
			s := NewScenario(fmt.Sprintf("sc-%d", n), "concurrent", "test", "perf", steps)
			twin := NewOrgTwin(fmt.Sprintf("tw-%d", n), "ten", nil, nil, nil, nil)
			s.Run(twin)
		}(i)
	}
	wg.Wait()
}

// ────────────────────────────────────────────────────────────────────────
// Budget sim with 20 adjustments
// ────────────────────────────────────────────────────────────────────────

func TestStress_BudgetSim20Adjustments(t *testing.T) {
	runner := NewRunner()
	adjustments := make([]BudgetAdjustment, 20)
	for i := 0; i < 20; i++ {
		adjustments[i] = BudgetAdjustment{Category: fmt.Sprintf("cat-%d", i), ChangeType: "INCREASE", AmountCents: 5000}
	}
	result, err := runner.RunBudgetSim(BudgetSimulation{
		SimID: "bs-1", BudgetID: "b1", Scenario: "GROWTH", Adjustments: adjustments, Duration: 30 * 24 * time.Hour,
	})
	if err != nil || result == nil {
		t.Fatalf("budget sim failed: err=%v", err)
	}
	if result.ProjectedSpendCents != 100000 {
		t.Fatalf("expected 100000 spend, got %d", result.ProjectedSpendCents)
	}
}

func TestStress_BudgetSimNoID(t *testing.T) {
	runner := NewRunner()
	_, err := runner.RunBudgetSim(BudgetSimulation{})
	if err == nil {
		t.Fatal("expected error for missing sim_id")
	}
}

func TestStress_BudgetSimDecreaseAdjustment(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunBudgetSim(BudgetSimulation{
		SimID: "bs-2", Adjustments: []BudgetAdjustment{{ChangeType: "DECREASE", AmountCents: 10000}}, Duration: 30 * 24 * time.Hour,
	})
	if result.ProjectedSpendCents != -10000 {
		t.Fatalf("expected -10000, got %d", result.ProjectedSpendCents)
	}
}

func TestStress_BudgetSimSetAdjustment(t *testing.T) {
	runner := NewRunner()
	result, _ := runner.RunBudgetSim(BudgetSimulation{
		SimID: "bs-3", Adjustments: []BudgetAdjustment{{ChangeType: "SET", AmountCents: 50000}}, Duration: 30 * 24 * time.Hour,
	})
	if result.ProjectedSpendCents != 50000 {
		t.Fatalf("expected 50000, got %d", result.ProjectedSpendCents)
	}
}

func TestStress_BudgetSimRiskLevels(t *testing.T) {
	if classifyBudgetRisk(500) != "LOW" {
		t.Fatal("expected LOW")
	}
	if classifyBudgetRisk(200000) != "MEDIUM" {
		t.Fatal("expected MEDIUM")
	}
	if classifyBudgetRisk(600000) != "HIGH" {
		t.Fatal("expected HIGH")
	}
	if classifyBudgetRisk(2000000) != "CRITICAL" {
		t.Fatal("expected CRITICAL")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Staffing sim with 10 types
// ────────────────────────────────────────────────────────────────────────

func TestStress_StaffingSim10Types(t *testing.T) {
	runner := NewRunner()
	workers := make([]StaffEntry, 10)
	for i := 0; i < 10; i++ {
		workers[i] = StaffEntry{
			ActorType: fmt.Sprintf("type-%d", i), Role: "worker", Count: i + 1,
			CostPerHour: 50.0, Utilization: 0.8, AvailableHours: 40.0,
		}
	}
	result, err := runner.RunStaffingSim(StaffingModel{ModelID: "sm-1", Workers: workers})
	if err != nil || result == nil {
		t.Fatalf("staffing sim failed: err=%v", err)
	}
	if len(result.HeadcountByType) != 10 {
		t.Fatalf("expected 10 types, got %d", len(result.HeadcountByType))
	}
}

func TestStress_StaffingSimNoID(t *testing.T) {
	runner := NewRunner()
	_, err := runner.RunStaffingSim(StaffingModel{})
	if err == nil {
		t.Fatal("expected error for missing model_id")
	}
}

func TestStress_StaffingSimTotalCost(t *testing.T) {
	runner := NewRunner()
	workers := []StaffEntry{{ActorType: "HUMAN", Role: "dev", Count: 2, CostPerHour: 100, Utilization: 1.0, AvailableHours: 40}}
	result, _ := runner.RunStaffingSim(StaffingModel{ModelID: "sm-2", Workers: workers})
	if result.TotalWeeklyCost != 8000 {
		t.Fatalf("expected 8000, got %f", result.TotalWeeklyCost)
	}
}

// ────────────────────────────────────────────────────────────────────────
// OrgTwin with 100 deltas
// ────────────────────────────────────────────────────────────────────────

func TestStress_OrgTwin100PolicyDeltas(t *testing.T) {
	basePolicies := make([]PolicyRule, 100)
	for i := 0; i < 100; i++ {
		basePolicies[i] = PolicyRule{ID: fmt.Sprintf("p-%d", i), Name: fmt.Sprintf("policy-%d", i), Enabled: true}
	}
	targetPolicies := make([]PolicyRule, 50)
	copy(targetPolicies, basePolicies[:50])
	for i := 50; i < 100; i++ {
		targetPolicies = append(targetPolicies, PolicyRule{ID: fmt.Sprintf("new-%d", i), Name: fmt.Sprintf("new-%d", i), Enabled: true})
	}
	base := NewOrgTwin("base", "t1", basePolicies, nil, nil, nil)
	target := NewOrgTwin("target", "t1", targetPolicies, nil, nil, nil)
	delta := Compare(base, target)
	if len(delta.RemovedPolicies) == 0 {
		t.Fatal("expected removed policies")
	}
	if len(delta.AddedPolicies) == 0 {
		t.Fatal("expected added policies")
	}
}

func TestStress_OrgTwinContentHash(t *testing.T) {
	twin := NewOrgTwin("tw-1", "ten-1", nil, nil, nil, nil)
	if twin.ContentHash == "" {
		t.Fatal("content hash not computed")
	}
}

func TestStress_OrgTwinStatusCurrent(t *testing.T) {
	twin := NewOrgTwin("tw-1", "ten-1", nil, nil, nil, nil)
	if twin.Status != TwinStatusCurrent {
		t.Fatalf("expected CURRENT, got %s", twin.Status)
	}
}

func TestStress_OrgTwinCompareNoChanges(t *testing.T) {
	policies := []PolicyRule{{ID: "p1", Name: "p", Enabled: true}}
	a := NewOrgTwin("a", "t", policies, nil, nil, nil)
	b := NewOrgTwin("b", "t", policies, nil, nil, nil)
	delta := Compare(a, b)
	if len(delta.AddedPolicies) != 0 || len(delta.RemovedPolicies) != 0 {
		t.Fatal("expected no policy changes")
	}
}

func TestStress_OrgTwinRoleDelta(t *testing.T) {
	base := NewOrgTwin("a", "t", nil, []RoleSnapshot{{RoleID: "r1"}, {RoleID: "r2"}}, nil, nil)
	target := NewOrgTwin("b", "t", nil, []RoleSnapshot{{RoleID: "r2"}, {RoleID: "r3"}}, nil, nil)
	delta := Compare(base, target)
	if len(delta.AddedRoles) != 1 || delta.AddedRoles[0] != "r3" {
		t.Fatalf("expected r3 added, got %v", delta.AddedRoles)
	}
}

func TestStress_SimulateDecisionAllowNoPolicy(t *testing.T) {
	twin := NewOrgTwin("t1", "ten", nil, nil, nil, nil)
	result := SimulateDecision(twin, "READ", "agent")
	if result.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", result.Decision)
	}
}

func TestStress_SimulateDecisionDenyWithPolicy(t *testing.T) {
	twin := NewOrgTwin("t1", "ten", []PolicyRule{{ID: "p1", EffectTypes: []string{"WRITE"}, Enabled: true}}, nil, nil, nil)
	result := SimulateDecision(twin, "WRITE", "agent")
	if result.Decision != "DENY" {
		t.Fatalf("expected DENY, got %s", result.Decision)
	}
}

func TestStress_SimulateDecisionContentHash(t *testing.T) {
	twin := NewOrgTwin("t1", "ten", nil, nil, nil, nil)
	result := SimulateDecision(twin, "READ", "agent")
	if result.ContentHash == "" {
		t.Fatal("content hash not set")
	}
}

func TestStress_RunnerListRuns(t *testing.T) {
	runner := NewRunner()
	_, _ = runner.RunBudgetSim(BudgetSimulation{SimID: "bs-1", Duration: time.Hour})
	_, _ = runner.RunStaffingSim(StaffingModel{ModelID: "sm-1", Workers: []StaffEntry{{ActorType: "H", Role: "r", Count: 1, CostPerHour: 1, AvailableHours: 1}}})
	runs := runner.ListRuns()
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(runs))
	}
}

func TestStress_RunnerGetRun(t *testing.T) {
	runner := NewRunner()
	_, _ = runner.RunBudgetSim(BudgetSimulation{SimID: "bs-x", Duration: time.Hour})
	run, err := runner.GetRun("bs-x")
	if err != nil || run.Status != "COMPLETED" {
		t.Fatalf("get run failed: err=%v status=%s", err, run.Status)
	}
}

func TestStress_RunnerGetRunNotFound(t *testing.T) {
	runner := NewRunner()
	_, err := runner.GetRun("missing")
	if err == nil {
		t.Fatal("expected error for missing run")
	}
}

func TestStress_TwinStatusConstants(t *testing.T) {
	if TwinStatusCurrent != "CURRENT" || TwinStatusStale != "STALE" || TwinStatusDraft != "DRAFT" {
		t.Fatal("twin status constants mismatch")
	}
}

func TestStress_ScenarioStatusConstants(t *testing.T) {
	if ScenarioStatusDraft != "DRAFT" || ScenarioStatusReady != "READY" || ScenarioStatusRunning != "RUNNING" || ScenarioStatusPassed != "PASSED" || ScenarioStatusFailed != "FAILED" {
		t.Fatal("scenario status constants mismatch")
	}
}

func TestStress_SimulateDecisionDisabledPolicy(t *testing.T) {
	twin := NewOrgTwin("t1", "ten", []PolicyRule{{ID: "p1", EffectTypes: []string{"READ"}, Enabled: false}}, nil, nil, nil)
	result := SimulateDecision(twin, "READ", "agent")
	if result.Decision != "ALLOW" {
		t.Fatalf("disabled policy should not deny: got %s", result.Decision)
	}
}

func TestStress_SimulateDecisionWildcardPolicy(t *testing.T) {
	twin := NewOrgTwin("t1", "ten", []PolicyRule{{ID: "p1", EffectTypes: []string{"*"}, Enabled: true}}, nil, nil, nil)
	result := SimulateDecision(twin, "ANYTHING", "agent")
	if result.Decision != "DENY" {
		t.Fatalf("wildcard policy should deny: got %s", result.Decision)
	}
}

func TestStress_SimulateDecisionTriggeredBy(t *testing.T) {
	twin := NewOrgTwin("t1", "ten", []PolicyRule{
		{ID: "p1", EffectTypes: []string{"WRITE"}, Enabled: true},
		{ID: "p2", EffectTypes: []string{"WRITE"}, Enabled: true},
	}, nil, nil, nil)
	result := SimulateDecision(twin, "WRITE", "agent")
	if len(result.TriggeredBy) != 2 {
		t.Fatalf("expected 2 triggered policies, got %d", len(result.TriggeredBy))
	}
}

func TestStress_OrgTwinCompareRemovedRoles(t *testing.T) {
	base := NewOrgTwin("a", "t", nil, []RoleSnapshot{{RoleID: "r1"}, {RoleID: "r2"}}, nil, nil)
	target := NewOrgTwin("b", "t", nil, []RoleSnapshot{{RoleID: "r2"}}, nil, nil)
	delta := Compare(base, target)
	if len(delta.RemovedRoles) != 1 || delta.RemovedRoles[0] != "r1" {
		t.Fatalf("expected r1 removed, got %v", delta.RemovedRoles)
	}
}

func TestStress_OrgTwinWithBudgets(t *testing.T) {
	budgets := []BudgetSnapshot{{BudgetID: "b1", AllocatedCents: 1000, SpentCents: 500, Currency: "USD"}}
	twin := NewOrgTwin("t1", "ten", nil, nil, budgets, nil)
	if len(twin.Budgets) != 1 || twin.Budgets[0].BudgetID != "b1" {
		t.Fatal("budgets not stored in twin")
	}
}

func TestStress_OrgTwinWithAuthorities(t *testing.T) {
	auth := []AuthoritySnapshot{{PrincipalID: "admin", Role: "ADMIN"}}
	twin := NewOrgTwin("t1", "ten", nil, nil, nil, auth)
	if len(twin.Authorities) != 1 {
		t.Fatal("authorities not stored")
	}
}

func TestStress_ScenarioValidateValid(t *testing.T) {
	s := NewScenario("id", "name", "desc", "cat", []ScenarioStep{{StepID: "s", Action: "a", Actor: "a", ExpectedDecision: "d"}})
	if s.Validate() != nil {
		t.Fatal("valid scenario failed validation")
	}
}

func TestStress_NewScenarioDefaults(t *testing.T) {
	s := NewScenario("id", "name", "desc", "security", []ScenarioStep{{StepID: "s", Action: "a", Actor: "a", ExpectedDecision: "ALLOW"}})
	if s.Status != ScenarioStatusDraft {
		t.Fatalf("expected DRAFT, got %s", s.Status)
	}
	if s.CreatedAt.IsZero() {
		t.Fatal("created_at should be set")
	}
}
