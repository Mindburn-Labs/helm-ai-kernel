// Package contracts defines the Judgment Taxonomy — the runtime classification
// system that formally separates autonomous acts from judgment-required ones.
//
// Per HELM 2030 Spec — Governed Judgment Calls:
//   - Every act is classified as autonomous or judgment-required
//   - The taxonomy is versioned, auditable, and drives PDP routing
//   - Classification can depend on effect type, blast radius, cost, and context
package contracts

import "time"

// JudgmentVerdict is the outcome of classifying an act.
type JudgmentVerdict string

const (
	// VerdictAutonomous means the act can proceed without human intervention.
	VerdictAutonomous JudgmentVerdict = "AUTONOMOUS"

	// VerdictJudgmentRequired means a human must approve before proceeding.
	VerdictJudgmentRequired JudgmentVerdict = "JUDGMENT_REQUIRED"

	// VerdictProhibited means the act is not allowed under any circumstances.
	VerdictProhibited JudgmentVerdict = "PROHIBITED"
)

// JudgmentRule defines a single classification rule in the taxonomy.
type JudgmentRule struct {
	// RuleID is the unique identifier for this rule.
	RuleID string `json:"rule_id"`

	// RuleName is a human-readable name.
	RuleName string `json:"rule_name"`

	// Priority determines evaluation order (higher = checked first).
	Priority int `json:"priority"`

	// Condition is a CEL expression that matches against JudgmentContext.
	// If empty, the rule matches all contexts.
	Condition string `json:"condition,omitempty"`

	// Verdict is the classification if this rule matches.
	Verdict JudgmentVerdict `json:"verdict"`

	// EscalationTemplate defines how to escalate if verdict is JUDGMENT_REQUIRED.
	EscalationTemplate *EscalationTemplate `json:"escalation_template,omitempty"`

	// Justification explains why this classification exists.
	Justification string `json:"justification,omitempty"`
}

// JudgmentContext is the input to the judgment classifier.
// It provides all the information needed to classify an act.
type JudgmentContext struct {
	EffectType        string `json:"effect_type"`
	EffectClass       string `json:"effect_class"` // E0..E4
	BlastRadius       string `json:"blast_radius"`
	EstimatedCost     int64  `json:"estimated_cost"`
	DataClass         string `json:"data_class"`
	Jurisdiction      string `json:"jurisdiction"`
	ActorType         string `json:"actor_type"` // human, operator, agent, service
	IsFirstOccurrence bool   `json:"is_first_occurrence"`
	CumulativeCost    int64  `json:"cumulative_cost"`
	EffectsInRun      int64  `json:"effects_in_run"`
}

// JudgmentDecision is the output of the judgment classifier.
type JudgmentDecision struct {
	Verdict            JudgmentVerdict     `json:"verdict"`
	MatchedRule        string              `json:"matched_rule"`
	TaxonomyVersion    string              `json:"taxonomy_version"`
	EscalationTemplate *EscalationTemplate `json:"escalation_template,omitempty"`
	Reasoning          string              `json:"reasoning"`
	DecidedAt          time.Time           `json:"decided_at"`
}

// EscalationTemplate defines the shape of an escalation request.
type EscalationTemplate struct {
	// ApproverRoles lists who can approve.
	ApproverRoles []string `json:"approver_roles"`

	// Quorum is how many approvals are needed.
	Quorum int `json:"quorum"`

	// TimeoutSeconds is how long to wait before auto-denying.
	TimeoutSeconds int `json:"timeout_seconds"`

	// RequiredContext specifies what context must be shown to approvers.
	RequiredContext []string `json:"required_context,omitempty"` // e.g., "plan", "diff", "cost_estimate", "rollback_plan"

	// OnTimeout is the action if approval times out.
	// Values: "deny", "escalate_further", "abort_run"
	OnTimeout string `json:"on_timeout"`
}

// JudgmentTaxonomyManifest is the versioned collection of all rules.
type JudgmentTaxonomyManifest struct {
	Version     string         `json:"version"`
	ContentHash string         `json:"content_hash"`
	Rules       []JudgmentRule `json:"rules"`
	UpdatedAt   time.Time      `json:"updated_at"`
	UpdatedBy   string         `json:"updated_by"`
}
