// Package contracts — decision_request.go defines the DecisionRequest protocol.
//
// A DecisionRequest is a first-class queued blocker that represents any point
// where HELM needs human input. It replaces open-ended AI back-and-forth with
// constrained, structured choices.
//
// Key invariants:
//   - Every DecisionRequest has 2–7 options (+ optional "Something else" and "Skip")
//   - Options are constrained and each carries an impact preview
//   - Resolving a DecisionRequest deterministically unblocks the associated run
//   - "Untitled" resources MUST trigger a DecisionRequest before creation
//   - All DecisionRequests produce receipts regardless of outcome
package contracts

import (
	"fmt"
	"time"
)

// ──────────────────────────────────────────────────────────────
// DecisionRequest Kind
// ──────────────────────────────────────────────────────────────

// DecisionRequestKind classifies the type of decision needed.
type DecisionRequestKind string

const (
	// DecisionKindApproval requires explicit approval for a proposed action.
	DecisionKindApproval DecisionRequestKind = "APPROVAL"

	// DecisionKindPolicyChoice asks the user to choose between policy-compliant options.
	DecisionKindPolicyChoice DecisionRequestKind = "POLICY_CHOICE"

	// DecisionKindClarification asks for missing information to proceed.
	DecisionKindClarification DecisionRequestKind = "CLARIFICATION"

	// DecisionKindSpending authorizes a spend above the autonomous threshold.
	DecisionKindSpending DecisionRequestKind = "SPENDING"

	// DecisionKindIrreversible confirms an irreversible action.
	DecisionKindIrreversible DecisionRequestKind = "IRREVERSIBLE"

	// DecisionKindSensitivePolicy authorizes a sensitive policy change.
	DecisionKindSensitivePolicy DecisionRequestKind = "SENSITIVE_POLICY"

	// DecisionKindNaming requires the user to name or title a resource (prevents "Untitled").
	DecisionKindNaming DecisionRequestKind = "NAMING"
)

// ──────────────────────────────────────────────────────────────
// DecisionRequest Status
// ──────────────────────────────────────────────────────────────

// DecisionRequestStatus tracks the lifecycle of a decision request.
type DecisionRequestStatus string

const (
	DecisionStatusPending  DecisionRequestStatus = "PENDING"
	DecisionStatusResolved DecisionRequestStatus = "RESOLVED"
	DecisionStatusExpired  DecisionRequestStatus = "EXPIRED"
	DecisionStatusSkipped  DecisionRequestStatus = "SKIPPED"
)

// ──────────────────────────────────────────────────────────────
// DecisionRequest Priority
// ──────────────────────────────────────────────────────────────

// DecisionPriority determines display ordering in the blocker queue.
type DecisionPriority string

const (
	DecisionPriorityUrgent DecisionPriority = "URGENT"
	DecisionPriorityHigh   DecisionPriority = "HIGH"
	DecisionPriorityNormal DecisionPriority = "NORMAL"
	DecisionPriorityLow    DecisionPriority = "LOW"
)

// ──────────────────────────────────────────────────────────────
// Impact Preview
// ──────────────────────────────────────────────────────────────

// DecisionImpactPreview summarizes the impact of choosing a particular option.
// All fields are deterministic — no model-generated prose.
type DecisionImpactPreview struct {
	// DiffSummary is a deterministic summary of what changes (e.g., "Add 3 nodes, remove 1 edge").
	DiffSummary string `json:"diff_summary"`

	// RiskDelta describes the change in risk level (e.g., "+1 ELEVATED → HIGH").
	RiskDelta string `json:"risk_delta"`

	// BudgetDeltaCents is the estimated cost impact in cents (negative = savings).
	BudgetDeltaCents int64 `json:"budget_delta_cents"`
}

// ──────────────────────────────────────────────────────────────
// Decision Option
// ──────────────────────────────────────────────────────────────

// DecisionOption is a single constrained choice within a DecisionRequest.
type DecisionOption struct {
	// ID is the machine-readable option identifier.
	ID string `json:"id"`

	// Label is the short human-readable option text (e.g., "Approve", "Use existing template").
	Label string `json:"label"`

	// Description is an optional longer explanation.
	Description string `json:"description,omitempty"`

	// ImpactPreview shows what happens if this option is chosen.
	ImpactPreview *DecisionImpactPreview `json:"impact_preview,omitempty"`

	// IsDefault marks this as the recommended/default option.
	IsDefault bool `json:"is_default,omitempty"`

	// IsSkip marks this as a "skip this decision" option (if allowed).
	IsSkip bool `json:"is_skip,omitempty"`

	// IsSomethingElse marks this as the "Something else" escape hatch.
	IsSomethingElse bool `json:"is_something_else,omitempty"`
}

// ──────────────────────────────────────────────────────────────
// DecisionRequest — the first-class queued blocker
// ──────────────────────────────────────────────────────────────

// DecisionRequest is a structured request for human input.
// It blocks the associated run until resolved, expired, or skipped.
//
// Design invariants:
//   - Exactly 2–7 concrete options (excluding meta-options like Skip/SomethingElse)
//   - Resolving deterministically unblocks the run (no ambiguity)
//   - Every DecisionRequest gets a receipt via the ops event stream
//
//nolint:govet // fieldalignment: struct layout matches JSON/UI display order
type DecisionRequest struct {
	// RequestID uniquely identifies this decision request.
	RequestID string `json:"request_id"`

	// Kind classifies the type of decision.
	Kind DecisionRequestKind `json:"kind"`

	// Title is the concise human-readable question (max 120 chars).
	Title string `json:"title"`

	// Description provides additional context if needed.
	Description string `json:"description,omitempty"`

	// Options are the constrained choices available.
	Options []DecisionOption `json:"options"`

	// ImpactPreview is the aggregate impact preview for the decision context.
	ImpactPreview *DecisionImpactPreview `json:"impact_preview,omitempty"`

	// RunID links to the run blocked by this decision (empty for global decisions).
	RunID string `json:"run_id,omitempty"`

	// Priority determines display ordering.
	Priority DecisionPriority `json:"priority"`

	// Status tracks the lifecycle.
	Status DecisionRequestStatus `json:"status"`

	// SkipAllowed indicates whether the user may skip this decision.
	SkipAllowed bool `json:"skip_allowed"`

	// CreatedAt is when the decision was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is the deadline for this decision (zero = no expiry).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// ResolvedOptionID is the chosen option ID (populated on resolution).
	ResolvedOptionID string `json:"resolved_option_id,omitempty"`

	// ResolvedBy is the principal who resolved the decision.
	ResolvedBy string `json:"resolved_by,omitempty"`

	// ResolvedAt is when the decision was resolved.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// FreeformResponse captures text when "Something else" is chosen.
	FreeformResponse string `json:"freeform_response,omitempty"`
}

// ──────────────────────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────────────────────

const (
	minConcreteOptions = 2
	maxConcreteOptions = 7
	maxTitleLength     = 120
)

// Validate checks that the DecisionRequest meets structural invariants.
func (dr *DecisionRequest) Validate() error {
	if dr.RequestID == "" {
		return fmt.Errorf("decision_request: request_id is required")
	}
	if dr.Title == "" {
		return fmt.Errorf("decision_request: title is required")
	}
	if len(dr.Title) > maxTitleLength {
		return fmt.Errorf("decision_request: title exceeds %d chars", maxTitleLength)
	}
	if dr.Kind == "" {
		return fmt.Errorf("decision_request: kind is required")
	}

	// Count concrete options (excluding meta-options).
	concreteCount := 0
	for _, opt := range dr.Options {
		if !opt.IsSkip && !opt.IsSomethingElse {
			concreteCount++
		}
	}

	if concreteCount < minConcreteOptions {
		return fmt.Errorf("decision_request: need at least %d concrete options, got %d", minConcreteOptions, concreteCount)
	}
	if concreteCount > maxConcreteOptions {
		return fmt.Errorf("decision_request: max %d concrete options, got %d", maxConcreteOptions, concreteCount)
	}

	// Validate option IDs are unique.
	seen := make(map[string]bool, len(dr.Options))
	for _, opt := range dr.Options {
		if opt.ID == "" {
			return fmt.Errorf("decision_request: option ID is required")
		}
		if seen[opt.ID] {
			return fmt.Errorf("decision_request: duplicate option ID %q", opt.ID)
		}
		seen[opt.ID] = true
	}

	return nil
}

// IsBlocking returns true if this decision is currently blocking progress.
func (dr *DecisionRequest) IsBlocking() bool {
	return dr.Status == DecisionStatusPending
}

// Resolve marks this decision as resolved with the given option.
func (dr *DecisionRequest) Resolve(optionID, resolvedBy string) error {
	if dr.Status != DecisionStatusPending {
		return fmt.Errorf("decision_request: cannot resolve non-pending request (status=%s)", dr.Status)
	}

	// Validate that the option exists.
	found := false
	for _, opt := range dr.Options {
		if opt.ID == optionID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("decision_request: unknown option ID %q", optionID)
	}

	now := time.Now().UTC()
	dr.Status = DecisionStatusResolved
	dr.ResolvedOptionID = optionID
	dr.ResolvedBy = resolvedBy
	dr.ResolvedAt = &now
	return nil
}

// Skip marks this decision as skipped (only if allowed).
func (dr *DecisionRequest) Skip(skippedBy string) error {
	if !dr.SkipAllowed {
		return fmt.Errorf("decision_request: skip is not allowed for this decision")
	}
	if dr.Status != DecisionStatusPending {
		return fmt.Errorf("decision_request: cannot skip non-pending request (status=%s)", dr.Status)
	}

	now := time.Now().UTC()
	dr.Status = DecisionStatusSkipped
	dr.ResolvedBy = skippedBy
	dr.ResolvedAt = &now
	return nil
}

// CheckExpiry marks the decision as expired if past its deadline.
func (dr *DecisionRequest) CheckExpiry() bool {
	if dr.Status != DecisionStatusPending {
		return false
	}
	if !dr.ExpiresAt.IsZero() && time.Now().UTC().After(dr.ExpiresAt) {
		dr.Status = DecisionStatusExpired
		return true
	}
	return false
}
