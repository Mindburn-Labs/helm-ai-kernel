// Package simulation — Scenario definitions.
//
// Per HELM 2030 Spec §5.8:
//
//	Scenarios are structured test cases for policy simulation.
//	They define a sequence of actions with expected outcomes.
package simulation

import (
	"errors"
	"time"
)

// ScenarioStatus tracks scenario state.
type ScenarioStatus string

const (
	ScenarioStatusDraft   ScenarioStatus = "DRAFT"
	ScenarioStatusReady   ScenarioStatus = "READY"
	ScenarioStatusRunning ScenarioStatus = "RUNNING"
	ScenarioStatusPassed  ScenarioStatus = "PASSED"
	ScenarioStatusFailed  ScenarioStatus = "FAILED"
)

// ScenarioStep is a single action in a scenario.
type ScenarioStep struct {
	StepID           string `json:"step_id"`
	Action           string `json:"action"`
	Actor            string `json:"actor"`
	Context          map[string]string `json:"context,omitempty"`
	ExpectedDecision string `json:"expected_decision"` // "ALLOW", "DENY", "ESCALATE"
	Description      string `json:"description"`
}

// ScenarioAssertion validates the scenario outcome.
type ScenarioAssertion struct {
	Field    string `json:"field"`    // JSON path to check
	Operator string `json:"operator"` // "eq", "ne", "gt", "lt", "contains"
	Value    string `json:"value"`
}

// Scenario is a structured test case for simulation.
type Scenario struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Description    string              `json:"description"`
	Category       string              `json:"category"` // "compliance", "security", "performance", "economic"
	Steps          []ScenarioStep      `json:"steps"`
	Assertions     []ScenarioAssertion `json:"assertions,omitempty"`
	ExpectedOutcome string             `json:"expected_outcome"` // "ALL_PASS", "PARTIAL", "ALL_DENY"
	Status         ScenarioStatus      `json:"status"`
	Results        []SimulationResult  `json:"results,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
}

// NewScenario creates a scenario.
func NewScenario(id, name, description, category string, steps []ScenarioStep) *Scenario {
	return &Scenario{
		ID:          id,
		Name:        name,
		Description: description,
		Category:    category,
		Steps:       steps,
		Status:      ScenarioStatusDraft,
		CreatedAt:   time.Now().UTC(),
	}
}

// Validate ensures the scenario is well-formed.
func (s *Scenario) Validate() error {
	if s.ID == "" {
		return errors.New("scenario: id is required")
	}
	if s.Name == "" {
		return errors.New("scenario: name is required")
	}
	if len(s.Steps) == 0 {
		return errors.New("scenario: at least one step required")
	}
	for _, step := range s.Steps {
		if step.Action == "" {
			return errors.New("scenario: step action is required")
		}
		if step.ExpectedDecision == "" {
			return errors.New("scenario: step expected_decision is required")
		}
	}
	return nil
}

// Run executes the scenario against an OrgTwin.
func (s *Scenario) Run(twin *OrgTwin) {
	s.Status = ScenarioStatusRunning
	s.Results = make([]SimulationResult, 0, len(s.Steps))

	allPass := true
	for _, step := range s.Steps {
		result := SimulateDecision(twin, step.Action, step.Actor)
		s.Results = append(s.Results, *result)
		if result.Decision != step.ExpectedDecision {
			allPass = false
		}
	}

	if allPass {
		s.Status = ScenarioStatusPassed
	} else {
		s.Status = ScenarioStatusFailed
	}
}

// PassRate returns the fraction of steps that matched expectations.
func (s *Scenario) PassRate() float64 {
	if len(s.Steps) == 0 || len(s.Results) == 0 {
		return 0
	}
	passed := 0
	for i, step := range s.Steps {
		if i < len(s.Results) && s.Results[i].Decision == step.ExpectedDecision {
			passed++
		}
	}
	return float64(passed) / float64(len(s.Steps))
}
