// Package governance — ConflictArbitration.
//
// Per HELM 2030 Spec §5.2:
//
//	When multiple governance rules conflict, the arbitration protocol
//	determines the resolution using priority, specificity, and temporal
//	precedence. Extends the existing denial engine.
package governance

import (
	"time"
)

// ConflictType classifies the nature of a governance conflict.
type ConflictType string

const (
	ConflictPolicyOverlap  ConflictType = "POLICY_OVERLAP"
	ConflictBudgetConflict ConflictType = "BUDGET_CONFLICT"
	ConflictAuthority      ConflictType = "AUTHORITY_CONFLICT"
	ConflictJurisdiction   ConflictType = "JURISDICTION_CONFLICT"
)

// ArbitrationStrategy defines how conflicts are resolved.
type ArbitrationStrategy string

const (
	StrategyStrictest ArbitrationStrategy = "STRICTEST_WINS"   // most restrictive policy prevails
	StrategySpecific  ArbitrationStrategy = "MOST_SPECIFIC"    // most specific scope wins
	StrategyPriority  ArbitrationStrategy = "PRIORITY_ORDERED" // explicit priority ordering
	StrategyEscalate  ArbitrationStrategy = "ESCALATE"         // escalate to human
)

// ConflictRecord documents a conflict between governance rules.
type ConflictRecord struct {
	ID         string              `json:"id"`
	Type       ConflictType        `json:"type"`
	RuleAID    string              `json:"rule_a_id"`
	RuleBID    string              `json:"rule_b_id"`
	DecisionA  string              `json:"decision_a"` // what rule A says
	DecisionB  string              `json:"decision_b"` // what rule B says
	Resolution string              `json:"resolution"` // final decision
	Strategy   ArbitrationStrategy `json:"strategy_used"`
	Reason     string              `json:"reason"`
	ResolvedAt time.Time           `json:"resolved_at"`
}

// ArbitrationInput is a set of conflicting rule decisions.
type ArbitrationInput struct {
	RuleID   string `json:"rule_id"`
	Decision string `json:"decision"` // "ALLOW", "DENY", "ESCALATE"
	Priority int    `json:"priority"`
	Scope    string `json:"scope"` // "GLOBAL", "ORG", "TEAM", "AGENT"
}

var scopePriority = map[string]int{
	"AGENT":  4,
	"TEAM":   3,
	"ORG":    2,
	"GLOBAL": 1,
}
