// Package governance provides security infrastructure for HELM.
// Per HELM Normative Addendum v1.5 Sections H, I, J.
package governance

import (
	"sync"
	"time"
)

// ============================================================================
// Section H: Delegation Revocation
// ============================================================================

// DelegationRevocationEntry represents a revoked delegation.
// Per Section H.1: Delegation revocation list entries.
type DelegationRevocationEntry struct {
	DelegationID string     `json:"delegation_id"`
	RevokedAt    time.Time  `json:"revoked_at"`
	RevokedBy    string     `json:"revoked_by"`
	Reason       string     `json:"reason,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // When entry can be pruned
}

// DelegationRevocationList maintains revoked delegations.
// Per Section H.2: The kernel MUST maintain a revocation list.
type DelegationRevocationList struct {
	mu      sync.RWMutex
	Version string                                `json:"version"`
	Entries map[string]*DelegationRevocationEntry `json:"entries"`
}

// ============================================================================
// Section I: Compensation Failure Escalation
// ============================================================================

// MaxCompensationAttempts is the default max retry count.
// Per Section I.1: Track compensation attempts.
const MaxCompensationAttempts = 3

// CompensationFailurePolicy defines the on_compensation_failure policy.
type CompensationFailurePolicy string

const (
	CompensationPolicyRetry    CompensationFailurePolicy = "RETRY"
	CompensationPolicyEscalate CompensationFailurePolicy = "ESCALATE"
	CompensationPolicyManual   CompensationFailurePolicy = "MANUAL_INTERVENTION"
	CompensationPolicyFallback CompensationFailurePolicy = "FALLBACK"
)

// CompensationState tracks compensation attempts.
// Per Section I.2: Compensation tracking state.
type CompensationState struct {
	TransactionID    string                    `json:"transaction_id"`
	OperationID      string                    `json:"operation_id"`
	AttemptCount     int                       `json:"attempt_count"`
	MaxAttempts      int                       `json:"max_attempts"`
	Policy           CompensationFailurePolicy `json:"policy"`
	LastAttemptAt    *time.Time                `json:"last_attempt_at,omitempty"`
	LastError        string                    `json:"last_error,omitempty"`
	EscalatedAt      *time.Time                `json:"escalated_at,omitempty"`
	FallbackExecuted bool                      `json:"fallback_executed"`
}

// CompensationOutcome represents the result of a compensation decision.
type CompensationOutcome string

const (
	CompensationOutcomeSuccess  CompensationOutcome = "SUCCESS"
	CompensationOutcomeRetry    CompensationOutcome = "RETRY"
	CompensationOutcomeEscalate CompensationOutcome = "ESCALATE"
	CompensationOutcomeManual   CompensationOutcome = "MANUAL"
	CompensationOutcomeFallback CompensationOutcome = "FALLBACK"
)

// ============================================================================
// Section J: PDP Compromise Detection
// ============================================================================

// PDPAttestationStatus indicates the attestation state.
type PDPAttestationStatus string

const (
	PDPAttestationValid       PDPAttestationStatus = "VALID"
	PDPAttestationExpired     PDPAttestationStatus = "EXPIRED"
	PDPAttestationRevoked     PDPAttestationStatus = "REVOKED"
	PDPAttestationSuspect     PDPAttestationStatus = "SUSPECT"
	PDPAttestationCompromised PDPAttestationStatus = "COMPROMISED"
)

// PDPAttestation represents a PDP's security attestation.
// Per Section J.1: PDP attestation mechanism.
type PDPAttestation struct {
	PDPID          string               `json:"pdp_id"`
	AttestationID  string               `json:"attestation_id"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	Status         PDPAttestationStatus `json:"status"`
	Hash           string               `json:"hash"` // Hash of PDP state/config
	IssuerID       string               `json:"issuer_id"`
	QuorumRequired int                  `json:"quorum_required,omitempty"`
}

// AnomalyType categorizes detected anomalies.
type AnomalyType string

const (
	AnomalyTypeDecisionDrift    AnomalyType = "DECISION_DRIFT"
	AnomalyTypeTimingAnomaly    AnomalyType = "TIMING_ANOMALY"
	AnomalyTypeResourceAbuse    AnomalyType = "RESOURCE_ABUSE"
	AnomalyTypeUnauthorizedCall AnomalyType = "UNAUTHORIZED_CALL"
)

// PDPAnomaly represents a detected anomaly.
// Per Section J.3: Anomaly detection.
type PDPAnomaly struct {
	AnomalyID    string      `json:"anomaly_id"`
	PDPID        string      `json:"pdp_id"`
	Type         AnomalyType `json:"type"`
	DetectedAt   time.Time   `json:"detected_at"`
	Description  string      `json:"description"`
	Severity     int         `json:"severity"` // 1-10
	Investigated bool        `json:"investigated"`
}

// CompromiseDetector monitors PDPs for compromise indicators.
// Per Section J.4: Compromise detection system.
type CompromiseDetector struct {
	mu           sync.RWMutex
	anomalies    []*PDPAnomaly
	thresholds   map[AnomalyType]int // Severity threshold for fail-closed
	attestations map[string]*PDPAttestation
}
