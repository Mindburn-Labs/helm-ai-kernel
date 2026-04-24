// Package authority defines the canonical authority evaluation contract for HELM.
//
// These interfaces and types define the public authority evaluation surface.
// The Authority Court engine (in the commercial HELM Platform) implements
// these canonical interfaces. By extracting the contract into OSS, any
// HELM-compatible implementation can depend on the authority model without
// importing commercial internals.
//
// Key invariant: Implementations MUST be fail-closed — any error results in DENY.
package authority

import (
	"context"
	"time"
)

// EvaluationResult represents the authorization decision outcome.
type EvaluationResult string

const (
	ResultAllow           EvaluationResult = "ALLOW"
	ResultDeny            EvaluationResult = "DENY"
	ResultRequireApproval EvaluationResult = "REQUIRE_APPROVAL"
	ResultRequireEvidence EvaluationResult = "REQUIRE_EVIDENCE"
	ResultDefer           EvaluationResult = "DEFER"
)

// EvaluationRequest is the canonical input to the authority evaluation pipeline.
type EvaluationRequest struct {
	RequestID      string            `json:"request_id"`
	PrincipalID    string            `json:"principal_id"`
	PrincipalType  string            `json:"principal_type"`
	EffectTypes    []string          `json:"effect_types"`
	PolicyEpoch    string            `json:"policy_epoch"`
	IdempotencyKey string            `json:"idempotency_key"`
	Context        map[string]string `json:"context,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// EvaluationDecision is the canonical output of the authority evaluation pipeline.
type EvaluationDecision struct {
	DecisionID  string           `json:"decision_id"`
	RequestID   string           `json:"request_id"`
	Result      EvaluationResult `json:"result"`
	ReasonCodes []string         `json:"reason_codes"`
	PolicyEpoch string           `json:"policy_epoch"`
	IssuedAt    time.Time        `json:"issued_at"`
	ExpiresAt   time.Time        `json:"expires_at"`
	ContentHash string           `json:"content_hash"`
}

// Evaluator is the canonical authority evaluation interface.
// Implementations MUST be fail-closed: any error results in DENY.
type Evaluator interface {
	Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationDecision, error)
}
