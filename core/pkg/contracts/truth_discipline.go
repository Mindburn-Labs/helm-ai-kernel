// Package contracts — Truth Discipline primitives.
//
// Per the HELM Governed Autonomous Execution Plane spec, every plan,
// analysis, or action proposal must carry epistemic metadata: what is
// known, what is assumed, what is uncertain, and what evidence supports it.
//
// These types embed HitCC's truth discipline into HELM's contract layer.
package contracts

import "time"

// FactRef is a pointer to a verified fact that supports a plan step or decision.
type FactRef struct {
	// FactID is a unique identifier for this fact.
	FactID string `json:"fact_id"`

	// Source identifies where the fact came from (e.g., "git_log", "api_response", "user_input").
	Source string `json:"source"`

	// Claim is the factual statement.
	Claim string `json:"claim"`

	// VerifiedAt is when the fact was last verified.
	VerifiedAt time.Time `json:"verified_at,omitempty"`

	// Hash is a content-addressed hash of the evidence supporting this fact.
	Hash string `json:"hash,omitempty"`
}

// UnknownImpact classifies how an unknown affects execution.
type UnknownImpact string

const (
	// UnknownImpactBlocking means execution cannot proceed until resolved.
	UnknownImpactBlocking UnknownImpact = "blocking"

	// UnknownImpactDegrading means execution can proceed but with reduced confidence.
	UnknownImpactDegrading UnknownImpact = "degrading"

	// UnknownImpactInformational means the unknown is noted but does not affect execution.
	UnknownImpactInformational UnknownImpact = "informational"
)

// Unknown represents an unresolved question that may affect runtime, policy, or replay fidelity.
type Unknown struct {
	// ID is a unique identifier for this unknown.
	ID string `json:"id"`

	// Description explains what is not yet known.
	Description string `json:"description"`

	// Impact classifies how this unknown affects execution.
	Impact UnknownImpact `json:"impact"`

	// ResolutionStrategy describes how this unknown might be resolved.
	ResolutionStrategy string `json:"resolution_strategy,omitempty"`

	// BlockingStepIDs lists which plan steps are blocked by this unknown.
	BlockingStepIDs []string `json:"blocking_step_ids,omitempty"`
}

// TruthAnnotation is a reusable epistemic metadata bundle that can be
// attached to any contract type (plans, intents, decisions, receipts).
type TruthAnnotation struct {
	// FactSet lists verified facts supporting this element.
	FactSet []FactRef `json:"fact_set,omitempty"`

	// Assumptions lists unverified beliefs that the element depends on.
	Assumptions []string `json:"assumptions,omitempty"`

	// Unknowns lists unresolved questions.
	Unknowns []Unknown `json:"unknowns,omitempty"`

	// Confidence is a 0.0–1.0 score indicating overall epistemic confidence.
	Confidence float64 `json:"confidence,omitempty"`

	// EvidenceRefs lists content-addressed hashes of supporting evidence.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`

	// BlockingQuestions lists questions that must be answered before proceeding.
	BlockingQuestions []string `json:"blocking_questions,omitempty"`
}
