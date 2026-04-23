// Package governance provides security infrastructure for HELM.
// Per HELM Normative Addendum v1.5 Sections H, I, J.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// NewDelegationRevocationList creates a new revocation list.
func NewDelegationRevocationList() *DelegationRevocationList {
	return &DelegationRevocationList{
		Version: "1.0.0",
		Entries: make(map[string]*DelegationRevocationEntry),
	}
}

// Revoke adds a delegation to the revocation list.
func (drl *DelegationRevocationList) Revoke(delegationID, revokedBy, reason string) error {
	drl.mu.Lock()
	defer drl.mu.Unlock()

	if _, exists := drl.Entries[delegationID]; exists {
		return fmt.Errorf("delegation %s already revoked", delegationID)
	}

	drl.Entries[delegationID] = &DelegationRevocationEntry{
		DelegationID: delegationID,
		RevokedAt:    time.Now().UTC(),
		RevokedBy:    revokedBy,
		Reason:       reason,
	}

	return nil
}

// IsRevoked checks if a delegation is revoked.
func (drl *DelegationRevocationList) IsRevoked(delegationID string) bool {
	drl.mu.RLock()
	defer drl.mu.RUnlock()

	_, exists := drl.Entries[delegationID]
	return exists
}

// GetEntry retrieves a revocation entry.
func (drl *DelegationRevocationList) GetEntry(delegationID string) (*DelegationRevocationEntry, bool) {
	drl.mu.RLock()
	defer drl.mu.RUnlock()

	entry, exists := drl.Entries[delegationID]
	return entry, exists
}

// PruneExpired removes entries past their expiry.
func (drl *DelegationRevocationList) PruneExpired() int {
	drl.mu.Lock()
	defer drl.mu.Unlock()

	now := time.Now().UTC()
	count := 0

	for id, entry := range drl.Entries {
		if entry.ExpiresAt != nil && entry.ExpiresAt.Before(now) {
			delete(drl.Entries, id)
			count++
		}
	}

	return count
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

// NewCompensationState creates a new compensation tracking state.
func NewCompensationState(txID, opID string, policy CompensationFailurePolicy) *CompensationState {
	return &CompensationState{
		TransactionID: txID,
		OperationID:   opID,
		AttemptCount:  0,
		MaxAttempts:   MaxCompensationAttempts,
		Policy:        policy,
	}
}

// RecordAttempt records a compensation attempt.
func (cs *CompensationState) RecordAttempt(success bool, errorMsg string) CompensationOutcome {
	now := time.Now().UTC()
	cs.AttemptCount++
	cs.LastAttemptAt = &now

	if success {
		return CompensationOutcomeSuccess
	}

	cs.LastError = errorMsg

	if cs.AttemptCount >= cs.MaxAttempts {
		return cs.handleMaxAttemptsReached()
	}

	return CompensationOutcomeRetry
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

// handleMaxAttemptsReached applies the policy when max attempts reached.
func (cs *CompensationState) handleMaxAttemptsReached() CompensationOutcome {
	now := time.Now().UTC()

	switch cs.Policy {
	case CompensationPolicyEscalate:
		cs.EscalatedAt = &now
		return CompensationOutcomeEscalate
	case CompensationPolicyManual:
		return CompensationOutcomeManual
	case CompensationPolicyFallback:
		cs.FallbackExecuted = true
		return CompensationOutcomeFallback
	default:
		return CompensationOutcomeEscalate
	}
}

// NeedsIntervention checks if manual intervention is required.
func (cs *CompensationState) NeedsIntervention() bool {
	return cs.EscalatedAt != nil || (cs.AttemptCount >= cs.MaxAttempts && cs.Policy == CompensationPolicyManual)
}

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

// NewPDPAttestation creates a new attestation.
func NewPDPAttestation(pdpID string, validity time.Duration) *PDPAttestation {
	now := time.Now().UTC()
	attID := generateAttestationID(pdpID, now)

	return &PDPAttestation{
		PDPID:         pdpID,
		AttestationID: attID,
		IssuedAt:      now,
		ExpiresAt:     now.Add(validity),
		Status:        PDPAttestationValid,
	}
}

// generateAttestationID creates a deterministic attestation ID.
func generateAttestationID(pdpID string, issuedAt time.Time) string {
	data := fmt.Sprintf("%s:%d", pdpID, issuedAt.UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("att-%s", hex.EncodeToString(hash[:8]))
}

// IsValid checks if the attestation is valid.
func (a *PDPAttestation) IsValid() bool {
	return a.Status == PDPAttestationValid && time.Now().UTC().Before(a.ExpiresAt)
}

// Revoke marks the attestation as revoked.
func (a *PDPAttestation) Revoke() {
	a.Status = PDPAttestationRevoked
}

// MarkSuspect marks the attestation as suspect (pending investigation).
func (a *PDPAttestation) MarkSuspect() {
	a.Status = PDPAttestationSuspect
}

// MarkCompromised marks the attestation as compromised.
func (a *PDPAttestation) MarkCompromised() {
	a.Status = PDPAttestationCompromised
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

// NewCompromiseDetector creates a new detector.
func NewCompromiseDetector() *CompromiseDetector {
	return &CompromiseDetector{
		anomalies: make([]*PDPAnomaly, 0),
		thresholds: map[AnomalyType]int{
			AnomalyTypeDecisionDrift:    7,
			AnomalyTypeTimingAnomaly:    5,
			AnomalyTypeResourceAbuse:    6,
			AnomalyTypeUnauthorizedCall: 8,
		},
		attestations: make(map[string]*PDPAttestation),
	}
}

// RegisterAttestation registers a PDP attestation.
func (cd *CompromiseDetector) RegisterAttestation(att *PDPAttestation) {
	cd.mu.Lock()
	defer cd.mu.Unlock()
	cd.attestations[att.PDPID] = att
}

// ReportAnomaly records a detected anomaly.
func (cd *CompromiseDetector) ReportAnomaly(pdpID string, anomalyType AnomalyType, description string, severity int) *PDPAnomaly {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	anomaly := &PDPAnomaly{
		AnomalyID:   fmt.Sprintf("anomaly-%d", len(cd.anomalies)+1),
		PDPID:       pdpID,
		Type:        anomalyType,
		DetectedAt:  time.Now().UTC(),
		Description: description,
		Severity:    severity,
	}

	cd.anomalies = append(cd.anomalies, anomaly)

	// Check if fail-closed should trigger
	threshold, exists := cd.thresholds[anomalyType]
	if exists && severity >= threshold {
		if att, ok := cd.attestations[pdpID]; ok {
			att.MarkSuspect()
		}
	}

	return anomaly
}

// GetPDPStatus returns the security status of a PDP.
func (cd *CompromiseDetector) GetPDPStatus(pdpID string) PDPAttestationStatus {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	att, exists := cd.attestations[pdpID]
	if !exists {
		return PDPAttestationExpired // No attestation = not trusted
	}

	if !att.IsValid() {
		return att.Status
	}

	return PDPAttestationValid
}

// ShouldFailClosed determines if a PDP should fail closed.
// Per Section J.5: Fail-closed response mechanism.
func (cd *CompromiseDetector) ShouldFailClosed(pdpID string) bool {
	status := cd.GetPDPStatus(pdpID)
	return status == PDPAttestationSuspect ||
		status == PDPAttestationCompromised ||
		status == PDPAttestationRevoked
}
