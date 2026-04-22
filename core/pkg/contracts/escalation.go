// Package contracts defines the Escalation Intent Protocol — the structured
// mechanism for requesting human judgment with full context.
//
// Per HELM 2030 Spec — Governed Judgment Calls:
//   - Escalation carries plan, diff, risks, and rollback
//   - Approvers see structured context, not raw data
//   - Every escalation produces a receipt regardless of outcome
package contracts

import "time"

// EscalationIntent is a formal request for human judgment.
// It carries all the context an approver needs to make an informed decision.
type EscalationIntent struct {
	// Identity
	IntentID   string `json:"intent_id"`
	RunID      string `json:"run_id"`
	EnvelopeID string `json:"envelope_id"`

	// What triggered this escalation
	TriggerRule string          `json:"trigger_rule"` // JudgmentRule.RuleID
	Verdict     JudgmentVerdict `json:"verdict"`

	// The effect being held for judgment
	HeldEffect HeldEffect `json:"held_effect"`

	// Context for the approver
	Context EscalationContext `json:"context"`

	// Approval requirements
	Approval ApprovalSpec `json:"approval"`

	// Timing
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// Current status
	Status EscalationStatus `json:"status"`
}

// HeldEffect describes the effect waiting for judgment.
type HeldEffect struct {
	EffectType    string `json:"effect_type"`
	EffectClass   string `json:"effect_class"`
	PayloadHash   string `json:"payload_hash"`
	Description   string `json:"description"`    // Human-readable summary
	EstimatedCost int64  `json:"estimated_cost"` // In cents
	BlastRadius   string `json:"blast_radius"`
}

// EscalationContext provides all the information an approver needs.
type EscalationContext struct {
	// Plan shows what the system intends to do.
	Plan *EscalationPlan `json:"plan,omitempty"`

	// Diff shows what will change compared to current state.
	Diff *EscalationDiff `json:"diff,omitempty"`

	// Risks lists identified risks of proceeding.
	Risks []IdentifiedRisk `json:"risks,omitempty"`

	// RollbackPlan describes how to undo the effect if needed.
	RollbackPlan *RollbackPlan `json:"rollback_plan,omitempty"`

	// RunSummary provides context on the current run state.
	RunSummary *RunSummary `json:"run_summary,omitempty"`
}

// EscalationPlan describes the intended actions.
type EscalationPlan struct {
	Summary string   `json:"summary"`
	Steps   []string `json:"steps"`
}

// EscalationDiff shows before/after state.
type EscalationDiff struct {
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
	Patch  string         `json:"patch,omitempty"` // RFC 6902 JSON Patch or human-readable diff
}

// IdentifiedRisk describes a risk of proceeding.
type IdentifiedRisk struct {
	Category    string `json:"category"` // financial, compliance, operational, security
	Severity    string `json:"severity"` // low, medium, high, critical
	Description string `json:"description"`
	Mitigation  string `json:"mitigation,omitempty"`
}

// RollbackPlan describes how to undo the effect.
type RollbackPlan struct {
	Strategy    string `json:"strategy"` // automatic, manual, impossible
	Description string `json:"description"`
	TimeWindow  int    `json:"time_window_seconds,omitempty"` // How long rollback is available
}

// RunSummary summarizes the current run state for context.
type RunSummary struct {
	TotalEffects   int64  `json:"total_effects"`
	TotalCost      int64  `json:"total_cost"`
	ElapsedSeconds int64  `json:"elapsed_seconds"`
	EnvelopeID     string `json:"envelope_id"`
}

// ApprovalSpec defines who can approve and how.
type ApprovalSpec struct {
	ApproverRoles  []string `json:"approver_roles"`
	Quorum         int      `json:"quorum"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	OnTimeout      string   `json:"on_timeout"` // deny, escalate_further, abort_run
}

// EscalationStatus tracks the lifecycle of an escalation.
type EscalationStatus string

const (
	EscalationStatusPending  EscalationStatus = "PENDING"
	EscalationStatusApproved EscalationStatus = "APPROVED"
	EscalationStatusDenied   EscalationStatus = "DENIED"
	EscalationStatusTimedOut EscalationStatus = "TIMED_OUT"
	EscalationStatusAborted  EscalationStatus = "ABORTED"
)

// EscalationReceipt is the immutable record of an escalation outcome.
type EscalationReceipt struct {
	ReceiptID   string           `json:"receipt_id"`
	IntentID    string           `json:"intent_id"`
	Outcome     EscalationStatus `json:"outcome"`
	ApprovedBy  []string         `json:"approved_by,omitempty"`
	DeniedBy    string           `json:"denied_by,omitempty"`
	DenyReason  string           `json:"deny_reason,omitempty"`
	ResolvedAt  time.Time        `json:"resolved_at"`
	DurationMs  int64            `json:"duration_ms"`
	ContentHash string           `json:"content_hash"` // Hash of intent + outcome for audit
}
