// Package governance — ConflictArbitration.
//
// Per HELM 2030 Spec §5.2:
//
//	When multiple governance rules conflict, the arbitration protocol
//	determines the resolution using priority, specificity, and temporal
//	precedence. Extends the existing denial engine.
package governance

import (
	"sort"
	"time"
)

// ConflictType classifies the nature of a governance conflict.
type ConflictType string

const (
	ConflictPolicyOverlap   ConflictType = "POLICY_OVERLAP"
	ConflictBudgetConflict  ConflictType = "BUDGET_CONFLICT"
	ConflictAuthority       ConflictType = "AUTHORITY_CONFLICT"
	ConflictJurisdiction    ConflictType = "JURISDICTION_CONFLICT"
)

// ArbitrationStrategy defines how conflicts are resolved.
type ArbitrationStrategy string

const (
	StrategyStrictest    ArbitrationStrategy = "STRICTEST_WINS"   // most restrictive policy prevails
	StrategySpecific     ArbitrationStrategy = "MOST_SPECIFIC"    // most specific scope wins
	StrategyPriority     ArbitrationStrategy = "PRIORITY_ORDERED" // explicit priority ordering
	StrategyEscalate     ArbitrationStrategy = "ESCALATE"         // escalate to human
)

// ConflictRecord documents a conflict between governance rules.
type ConflictRecord struct {
	ID           string       `json:"id"`
	Type         ConflictType `json:"type"`
	RuleAID      string       `json:"rule_a_id"`
	RuleBID      string       `json:"rule_b_id"`
	DecisionA    string       `json:"decision_a"` // what rule A says
	DecisionB    string       `json:"decision_b"` // what rule B says
	Resolution   string       `json:"resolution"` // final decision
	Strategy     ArbitrationStrategy `json:"strategy_used"`
	Reason       string       `json:"reason"`
	ResolvedAt   time.Time    `json:"resolved_at"`
}

// ArbitrationInput is a set of conflicting rule decisions.
type ArbitrationInput struct {
	RuleID   string `json:"rule_id"`
	Decision string `json:"decision"` // "ALLOW", "DENY", "ESCALATE"
	Priority int    `json:"priority"`
	Scope    string `json:"scope"` // "GLOBAL", "ORG", "TEAM", "AGENT"
}

// Arbitrate resolves conflicts between multiple rule decisions.
// Default strategy: STRICTEST_WINS (deny trumps allow).
func Arbitrate(inputs []ArbitrationInput, strategy ArbitrationStrategy) *ConflictRecord {
	if len(inputs) <= 1 {
		return nil // no conflict
	}

	switch strategy {
	case StrategyStrictest:
		return arbitrateStrictest(inputs)
	case StrategyPriority:
		return arbitratePriority(inputs)
	case StrategySpecific:
		return arbitrateSpecific(inputs)
	default:
		return arbitrateStrictest(inputs) // fail to strictest
	}
}

func arbitrateStrictest(inputs []ArbitrationInput) *ConflictRecord {
	// DENY > ESCALATE > ALLOW
	decision := "ALLOW"
	var winnerID, loserID string
	for _, in := range inputs {
		if in.Decision == "DENY" {
			decision = "DENY"
			winnerID = in.RuleID
		} else if in.Decision == "ESCALATE" && decision != "DENY" {
			decision = "ESCALATE"
			winnerID = in.RuleID
		}
		if winnerID == "" {
			winnerID = in.RuleID
		} else if in.RuleID != winnerID {
			loserID = in.RuleID
		}
	}

	return &ConflictRecord{
		Type:       ConflictPolicyOverlap,
		RuleAID:    winnerID,
		RuleBID:    loserID,
		Resolution: decision,
		Strategy:   StrategyStrictest,
		Reason:     "strictest policy prevails",
		ResolvedAt: time.Now().UTC(),
	}
}

func arbitratePriority(inputs []ArbitrationInput) *ConflictRecord {
	sort.Slice(inputs, func(i, j int) bool {
		return inputs[i].Priority > inputs[j].Priority
	})
	winner := inputs[0]
	loser := inputs[len(inputs)-1]

	return &ConflictRecord{
		Type:       ConflictPolicyOverlap,
		RuleAID:    winner.RuleID,
		RuleBID:    loser.RuleID,
		DecisionA:  winner.Decision,
		DecisionB:  loser.Decision,
		Resolution: winner.Decision,
		Strategy:   StrategyPriority,
		Reason:     "highest priority rule prevails",
		ResolvedAt: time.Now().UTC(),
	}
}

var scopePriority = map[string]int{
	"AGENT": 4,
	"TEAM":  3,
	"ORG":   2,
	"GLOBAL": 1,
}

func arbitrateSpecific(inputs []ArbitrationInput) *ConflictRecord {
	sort.Slice(inputs, func(i, j int) bool {
		return scopePriority[inputs[i].Scope] > scopePriority[inputs[j].Scope]
	})
	winner := inputs[0]
	loser := inputs[len(inputs)-1]

	return &ConflictRecord{
		Type:       ConflictPolicyOverlap,
		RuleAID:    winner.RuleID,
		RuleBID:    loser.RuleID,
		DecisionA:  winner.Decision,
		DecisionB:  loser.Decision,
		Resolution: winner.Decision,
		Strategy:   StrategySpecific,
		Reason:     "most specific scope prevails",
		ResolvedAt: time.Now().UTC(),
	}
}
