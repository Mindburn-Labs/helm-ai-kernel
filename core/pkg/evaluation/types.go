// Package evaluation defines the public contracts for the HELM Evaluation / Oracle layer.
//
// Evaluation provides the canonical interfaces for running acceptance suites,
// evaluating pack compliance, and verifying phenotype correctness. This OSS
// package defines the specification types and runner interfaces. The commercial
// HELM Platform provides managed evaluation infrastructure.
package evaluation

import "time"

// EvalSpec defines a single evaluation specification.
type EvalSpec struct {
	SpecID      string         `json:"spec_id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Type        string         `json:"type"` // "PACK", "PHENOTYPE", "CONFORMANCE"
	Fixtures    []ScenarioFixture `json:"fixtures"`
	Assertions  []Assertion    `json:"assertions"`
	Timeout     time.Duration  `json:"timeout"`
}

// ScenarioFixture is a pre-configured test scenario.
type ScenarioFixture struct {
	FixtureID   string         `json:"fixture_id"`
	Name        string         `json:"name"`
	Input       map[string]any `json:"input"`
	Expected    map[string]any `json:"expected,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// Assertion defines what must be true after evaluation.
type Assertion struct {
	AssertionID string `json:"assertion_id"`
	Description string `json:"description"`
	Expression  string `json:"expression"` // CEL expression
	Severity    string `json:"severity"`   // "MUST", "SHOULD", "MAY"
}

// EvalResult is the outcome of running an evaluation spec.
type EvalResult struct {
	SpecID       string           `json:"spec_id"`
	Passed       bool             `json:"passed"`
	Score        float64          `json:"score"` // 0.0 to 1.0
	Details      []AssertionResult `json:"details"`
	Duration     time.Duration    `json:"duration"`
	ExecutedAt   time.Time        `json:"executed_at"`
	ContentHash  string           `json:"content_hash"`
}

// AssertionResult is the outcome of a single assertion.
type AssertionResult struct {
	AssertionID string `json:"assertion_id"`
	Passed      bool   `json:"passed"`
	Actual      any    `json:"actual,omitempty"`
	Message     string `json:"message,omitempty"`
}

// AcceptanceRunner is the canonical interface for running evaluation suites.
type AcceptanceRunner interface {
	Run(spec *EvalSpec) (*EvalResult, error)
	RunSuite(specs []*EvalSpec) ([]*EvalResult, error)
}
