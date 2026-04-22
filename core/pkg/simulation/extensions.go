// Package simulation — Extended simulation primitives.
//
// Per HELM 2030 Spec §5.8:
//
//	HELM MUST include budget simulation, staffing simulation,
//	digital-physical rehearsal, and stress testing capabilities.
//
// Resolves: GAP-A18, GAP-A19, GAP-A20.
package simulation

import "time"

// ── GAP-A18: Budget and Stress Simulation ────────────────────────

// BudgetSimulation models a budget scenario for what-if analysis.
type BudgetSimulation struct {
	SimID        string              `json:"sim_id"`
	BudgetID     string              `json:"budget_id"`
	Scenario     string              `json:"scenario"` // "GROWTH", "CONTRACTION", "HIRING_SURGE", "CUSTOM"
	Adjustments  []BudgetAdjustment  `json:"adjustments"`
	Duration     time.Duration       `json:"duration"`
	Results      *BudgetSimResult    `json:"results,omitempty"`
}

// BudgetAdjustment is a single change in a budget simulation.
type BudgetAdjustment struct {
	Category     string  `json:"category"`
	ChangeType   string  `json:"change_type"` // "INCREASE", "DECREASE", "SET"
	AmountCents  int64   `json:"amount_cents,omitempty"`
	Percentage   float64 `json:"percentage,omitempty"` // for proportional changes
}

// BudgetSimResult is the outcome of a budget simulation.
type BudgetSimResult struct {
	ProjectedSpendCents  int64   `json:"projected_spend_cents"`
	ProjectedRemaining   int64   `json:"projected_remaining_cents"`
	BurnRate             float64 `json:"burn_rate_per_month"`
	RunwayMonths         float64 `json:"runway_months"`
	OverBudget           bool    `json:"over_budget"`
	RiskLevel            string  `json:"risk_level"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
}

// StressTestRunner defines a stress test scenario.
type StressTestRunner struct {
	TestID       string           `json:"test_id"`
	Name         string           `json:"name"`
	Scenarios    []StressScenario `json:"scenarios"`
	Concurrency  int              `json:"concurrency"`
	DurationSecs int              `json:"duration_seconds"`
}

// StressScenario is a single stress test scenario.
type StressScenario struct {
	ScenarioID string `json:"scenario_id"`
	Type       string `json:"type"` // "LOAD", "SPIKE", "SOAK", "CHAOS"
	Target     string `json:"target"`     // what component to stress
	Intensity  int    `json:"intensity"`  // 1–10
}

// ── GAP-A19: Staffing Simulation ─────────────────────────────────

// StaffingModel models human/agent/robot workforce scenarios.
type StaffingModel struct {
	ModelID     string        `json:"model_id"`
	Workers     []StaffEntry  `json:"workers"`
	Projections []StaffChange `json:"projections,omitempty"`
}

// StaffEntry represents a workforce member in a simulation.
type StaffEntry struct {
	ActorType      string  `json:"actor_type"` // "HUMAN", "AGENT", "ROBOT"
	Role           string  `json:"role"`
	Count          int     `json:"count"`
	CostPerHour    float64 `json:"cost_per_hour"`
	Utilization    float64 `json:"utilization"` // 0.0–1.0
	AvailableHours float64 `json:"available_hours_per_week"`
}

// StaffChange is a requested workforce adjustment.
type StaffChange struct {
	EffectiveDate time.Time `json:"effective_date"`
	ActorType     string    `json:"actor_type"`
	Role          string    `json:"role"`
	Delta         int       `json:"delta"` // positive = hire, negative = reduce
	Reason        string    `json:"reason"`
}

// ── GAP-A20: Digital-Physical Rehearsal ──────────────────────────

// DigitalPhysicalRehearsal plans a rehearsal that spans digital and physical domains.
type DigitalPhysicalRehearsal struct {
	RehearsalID   string              `json:"rehearsal_id"`
	Name          string              `json:"name"`
	DigitalSteps  []RehearsalStep     `json:"digital_steps"`
	PhysicalSteps []RehearsalStep     `json:"physical_steps"`
	SafetyChecks  []SafetyCheck       `json:"safety_checks"`
	PreConditions []string            `json:"pre_conditions"`
	Status        string              `json:"status"` // "PLANNED", "IN_PROGRESS", "COMPLETED", "ABORTED"
}

// RehearsalStep is a single step in a digital-physical rehearsal.
type RehearsalStep struct {
	StepID      string `json:"step_id"`
	Domain      string `json:"domain"` // "DIGITAL", "PHYSICAL"
	Description string `json:"description"`
	ActorType   string `json:"actor_type"`
	Reversible  bool   `json:"reversible"`
	RiskLevel   string `json:"risk_level"`
}

// SafetyCheck is a safety validation in a rehearsal.
type SafetyCheck struct {
	CheckID    string `json:"check_id"`
	Type       string `json:"type"` // "PRE_FLIGHT", "IN_PROGRESS", "POST_ACTION"
	Condition  string `json:"condition"` // CEL expression
	FailAction string `json:"fail_action"` // "HALT", "ROLLBACK", "ALERT"
}
