// Package contracts — Phenotype contract format.
//
// Per HELM 2030 Spec §6.1.7:
//
//	HELM OSS MUST include inspectable operational phenotype definitions,
//	phenotype contract format, test fixtures, and execution constraints.
//
// Resolves: GAP-A24.
package contracts

import (
	"fmt"
	"time"
)

func errMissing(field string) error {
	return fmt.Errorf("phenotype contract validation: missing %s", field)
}

// PhenotypeContract defines the operational behavior and constraints
// of a phenotype — a concrete instantiation of organizational execution.
type PhenotypeContract struct {
	PhenotypeID   string               `json:"phenotype_id"`
	Name          string               `json:"name"`
	Version       string               `json:"version"`
	Description   string               `json:"description,omitempty"`
	AllowedTools  []string             `json:"allowed_tools"`
	BlockedTools  []string             `json:"blocked_tools,omitempty"`
	EffectBudget  PhenotypeEffectBudget `json:"effect_budget"`
	Constraints   []PhenotypeConstraint `json:"constraints"`
	EscalationRules []EscalationRule   `json:"escalation_rules,omitempty"`
	TTL           *time.Duration       `json:"ttl,omitempty"`
	RequiresReview bool                `json:"requires_review"`
}

// PhenotypeEffectBudget limits cumulative effects produced by a phenotype.
type PhenotypeEffectBudget struct {
	MaxTotalEffects    int   `json:"max_total_effects"`
	MaxCostCents       int64 `json:"max_cost_cents"`
	MaxExternalCalls   int   `json:"max_external_calls"`
	MaxDurationSecs    int   `json:"max_duration_seconds"`
}

// PhenotypeConstraint is a single constraint on phenotype execution.
type PhenotypeConstraint struct {
	ConstraintID string `json:"constraint_id"`
	Type         string `json:"type"` // "MAX_COST", "MAX_TIME", "REQUIRED_APPROVAL", "REGION_LOCK", "TOOL_LIMIT"
	Value        string `json:"value"`
	Enforcement  string `json:"enforcement"` // "HARD" (fail-closed), "SOFT" (warn + log)
}

// EscalationRule defines when a phenotype must escalate to a human.
type EscalationRule struct {
	Condition string `json:"condition"` // CEL expression
	EscalateTo string `json:"escalate_to"` // role or principal
	Timeout    int    `json:"timeout_seconds"`
}

// PhenotypeFixture is a test case for validating phenotype behavior.
type PhenotypeFixture struct {
	FixtureID     string            `json:"fixture_id"`
	PhenotypeID   string            `json:"phenotype_id"`
	Description   string            `json:"description"`
	Input         map[string]any    `json:"input"`
	ExpectedTools []string          `json:"expected_tools"`
	ExpectedDeny  bool              `json:"expected_deny"`
	MaxCostCents  int64             `json:"max_cost_cents"`
	Tags          []string          `json:"tags,omitempty"`
}

// ValidatePhenotype checks that a contract is structurally complete.
func ValidatePhenotype(p PhenotypeContract) error {
	if p.PhenotypeID == "" {
		return errMissing("phenotype_id")
	}
	if p.Name == "" {
		return errMissing("name")
	}
	if p.Version == "" {
		return errMissing("version")
	}
	if len(p.AllowedTools) == 0 && len(p.BlockedTools) == 0 {
		return errMissing("allowed_tools or blocked_tools")
	}
	if p.EffectBudget.MaxTotalEffects <= 0 {
		return errMissing("effect_budget.max_total_effects")
	}
	return nil
}
