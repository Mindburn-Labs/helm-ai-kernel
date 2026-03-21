package simulation

import (
	"testing"
)

func TestOrgTwinCreation(t *testing.T) {
	policies := []PolicyRule{
		{ID: "p-1", Name: "deny-high-risk", Expression: "risk > 0.8", EffectTypes: []string{"EXEC_SHELL"}, Enabled: true},
	}
	roles := []RoleSnapshot{
		{RoleID: "r-1", Name: "admin", Permissions: []string{"*"}, ActorCount: 2},
	}
	budgets := []BudgetSnapshot{
		{BudgetID: "b-1", Name: "Q1", AllocatedCents: 100000, SpentCents: 30000, Currency: "USD"},
	}

	twin := NewOrgTwin("twin-1", "t-1", policies, roles, budgets, nil)
	if twin.Status != TwinStatusCurrent {
		t.Fatalf("expected CURRENT, got %s", twin.Status)
	}
	if twin.ContentHash == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestOrgTwinCompare(t *testing.T) {
	base := NewOrgTwin("twin-1", "t-1",
		[]PolicyRule{{ID: "p-1", Name: "old"}},
		[]RoleSnapshot{{RoleID: "r-1", Name: "admin"}},
		nil, nil)

	target := NewOrgTwin("twin-2", "t-1",
		[]PolicyRule{{ID: "p-1", Name: "old"}, {ID: "p-2", Name: "new"}},
		[]RoleSnapshot{{RoleID: "r-2", Name: "editor"}},
		nil, nil)

	delta := Compare(base, target)
	if len(delta.AddedPolicies) != 1 || delta.AddedPolicies[0] != "p-2" {
		t.Fatalf("expected 1 added policy (p-2), got %v", delta.AddedPolicies)
	}
	if len(delta.RemovedRoles) != 1 || delta.RemovedRoles[0] != "r-1" {
		t.Fatalf("expected 1 removed role (r-1), got %v", delta.RemovedRoles)
	}
	if len(delta.AddedRoles) != 1 || delta.AddedRoles[0] != "r-2" {
		t.Fatalf("expected 1 added role (r-2), got %v", delta.AddedRoles)
	}
}

func TestSimulateDecision(t *testing.T) {
	twin := NewOrgTwin("twin-1", "t-1",
		[]PolicyRule{
			{ID: "p-1", Name: "block-shell", Expression: "deny", EffectTypes: []string{"EXEC_SHELL"}, Enabled: true},
		}, nil, nil, nil)

	// Action matching a policy effect type should be denied
	result := SimulateDecision(twin, "EXEC_SHELL", "agent-1")
	if result.Decision != "DENY" {
		t.Fatalf("expected DENY, got %s", result.Decision)
	}
	if len(result.TriggeredBy) != 1 {
		t.Fatalf("expected 1 triggered policy, got %d", len(result.TriggeredBy))
	}

	// Action not matching any policy should be allowed
	result = SimulateDecision(twin, "FS_READ", "agent-1")
	if result.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", result.Decision)
	}
}

func TestScenarioRunPass(t *testing.T) {
	twin := NewOrgTwin("twin-1", "t-1",
		[]PolicyRule{
			{ID: "p-1", Name: "block-shell", EffectTypes: []string{"EXEC_SHELL"}, Enabled: true},
		}, nil, nil, nil)

	scenario := NewScenario("s-1", "Shell Blocked", "verify shell is blocked", "security",
		[]ScenarioStep{
			{StepID: "1", Action: "EXEC_SHELL", Actor: "agent-1", ExpectedDecision: "DENY"},
			{StepID: "2", Action: "FS_READ", Actor: "agent-1", ExpectedDecision: "ALLOW"},
		})

	if err := scenario.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	scenario.Run(twin)
	if scenario.Status != ScenarioStatusPassed {
		t.Fatalf("expected PASSED, got %s", scenario.Status)
	}
	if scenario.PassRate() != 1.0 {
		t.Fatalf("expected 100%% pass rate, got %f", scenario.PassRate())
	}
}

func TestScenarioRunFail(t *testing.T) {
	twin := NewOrgTwin("twin-1", "t-1", nil, nil, nil, nil) // no policies

	scenario := NewScenario("s-1", "Expect Denial", "should fail", "security",
		[]ScenarioStep{
			{StepID: "1", Action: "EXEC_SHELL", Actor: "agent-1", ExpectedDecision: "DENY"},
		})

	scenario.Run(twin)
	if scenario.Status != ScenarioStatusFailed {
		t.Fatalf("expected FAILED, got %s", scenario.Status)
	}
}

func TestScenarioValidation(t *testing.T) {
	s := NewScenario("", "test", "desc", "security", nil)
	if err := s.Validate(); err == nil {
		t.Fatal("expected validation error for empty ID")
	}
	s = NewScenario("s-1", "test", "desc", "security", []ScenarioStep{})
	if err := s.Validate(); err == nil {
		t.Fatal("expected validation error for empty steps")
	}
}
