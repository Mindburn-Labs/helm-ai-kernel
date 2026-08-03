// quantum_posture: execution-intent signature metadata is algorithm-neutral;
// protection depends on the configured classical, ML-DSA, or hybrid verifier.
package contracts

import (
	"fmt"
	"strings"
	"time"
)

// AccessRequest models a standard authorization check.
type AccessRequest struct {
	PrincipalID string                 `json:"principal_id"`
	Action      string                 `json:"action"`
	ResourceID  string                 `json:"resource_id"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// DecisionRecord captures the final judgment of the Policy Engine.
// It aligns with decision.proto
//
//nolint:govet // fieldalignment: struct layout matches proto schema
type DecisionRecord struct {
	ID         string `json:"id"`
	ProposalID string `json:"proposal_id"`
	// CorrelationID is the product request identity (X-Helm-Correlation-ID)
	// this decision was made for — the stable join key across lifecycle
	// events, receipts, and evidence (pilot business-telemetry contract §2).
	// NOTE: outside the decision signature until HELM-303 resolves.
	CorrelationID string `json:"correlation_id,omitempty"`
	StepID        string `json:"step_id"`
	PhenotypeHash string `json:"phenotype_hash"`
	PolicyVersion string `json:"policy_version"`

	// New Policy Engine Fields
	SubjectID string `json:"subject_id"` // Matches PrincipalID
	Action    string `json:"action"`
	Resource  string `json:"resource"`

	// V2: Cryptographic binding to effect semantics
	EffectDigest string `json:"effect_digest,omitempty"`

	// V2: Policy backend metadata for receipt binding (P0.1 competitive defense)
	PolicyBackend      string `json:"policy_backend,omitempty"`       // "helm" | "external"
	PolicyContentHash  string `json:"policy_content_hash,omitempty"`  // content-addressed policy version
	PolicyEpoch        string `json:"policy_epoch,omitempty"`         // active policy epoch bound to this decision
	PolicyDecisionHash string `json:"policy_decision_hash,omitempty"` // SHA-256 of canonical decision

	StateCursor    string         `json:"state_cursor"`
	Snapshot       string         `json:"snapshot,omitempty"` // Content-Addressed Artifact Content
	EnvFingerprint string         `json:"env_fingerprint"`
	Verdict        string         `json:"verdict"`                 // Canonical: ALLOW, DENY, ESCALATE
	Reason         string         `json:"reason"`                  // Human-readable explanation
	ReasonCode     string         `json:"reason_code,omitempty"`   // Machine-readable registry code
	InputContext   map[string]any `json:"input_context,omitempty"` // For explainability
	// ThreatScan is Guardian-owned typed threat evidence. Decisions with this
	// field use the V3 preimage, which binds the complete canonical reference
	// (including semantic model, score, and failure state).
	ThreatScan *ThreatScanRef `json:"threat_scan,omitempty"`
	// Session Risk Memory fields bind trajectory-level authorization state to the signed decision.
	TrajectoryRiskScore    float64 `json:"trajectory_risk_score,omitempty"`
	SessionCentroidHash    string  `json:"session_centroid_hash,omitempty"`
	RiskAccumulationWindow int     `json:"risk_accumulation_window,omitempty"`
	// RequirementSetHash links this decision to the specific Proof Requirement Graph rules satisfied.
	RequirementSetHash string `json:"requirement_set_hash,omitempty"`
	// GateRosterHash digests the Guardian gate roster (guardian.GateRoster)
	// that produced this verdict, so evidence states which gates ran instead
	// of leaving that to code review. An uninjected gate is skipped rather
	// than refused, so two kernels can return the same verdict from different
	// enforcement: without this the difference is invisible downstream.
	// NOTE: still outside the decision signature. DecisionRecordSignatureV2
	// (HELM-303) swapped free-text Reason for ReasonCode, and V3 binds typed
	// threat evidence; binding this roster needs a further preimage revision.
	// It remains tamper-evident via the receipt envelope chain hash.
	GateRosterHash string `json:"gate_roster_hash,omitempty"`
	Signature      string `json:"signature"`
	SignatureType  string `json:"signature_type"`
	// SignatureVersion names the signing-preimage revision. Empty = legacy
	// (free-text Reason in the preimage, ReasonCode absent).
	// DecisionRecordSignatureV2 signs the machine-readable ReasonCode instead
	// of prose: the field every downstream consumer keys on is the one the
	// signature attests. DecisionRecordSignatureV3 additionally binds typed
	// Guardian threat evidence when it is present. DecisionRecordSignatureV4
	// retains those facts and also binds the evaluated authority tuple and
	// signer metadata.
	SignatureVersion string    `json:"signature_version,omitempty"`
	Timestamp        time.Time `json:"timestamp"`

	// Intervention Metadata (Temporal Guardian)
	Intervention *InterventionMetadata `json:"intervention,omitempty"`
}

// InterventionType represents the type of intervention.
type InterventionType string

// Intervention type constants.
const (
	InterventionNone       InterventionType = "NONE"
	InterventionThrottle   InterventionType = "THROTTLE"
	InterventionInterrupt  InterventionType = "INTERRUPT"
	InterventionQuarantine InterventionType = "QUARANTINE"
)

// InterventionMetadata captures details about a temporal safety intervention.
type InterventionMetadata struct {
	Type         InterventionType `json:"type"`
	ReasonCode   string           `json:"reason_code"`             // e.g., "VELOCITY_LIMIT_EXCEEDED"
	WaitDuration time.Duration    `json:"wait_duration,omitempty"` // For throttling
	TokensSaved  int64            `json:"tokens_saved,omitempty"`  // Efficiency metric
}

// DecisionLogEvent represents an audit log entry for a decision.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type DecisionLogEvent struct {
	DecisionID     string            `json:"decision_id"`
	JurisdictionID string            `json:"jurisdiction_id,omitempty"`
	EffectType     string            `json:"effect_type,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
	Labels         map[string]string `json:"labels,omitempty"`

	// Structured Decision (Guardian)
	Decision *DecisionRecord `json:"decision,omitempty"`

	// OPA/Legacy fields
	Revision string `json:"revision,omitempty"`
	Path     string `json:"path,omitempty"`
	Input    any    `json:"input,omitempty"`
	Result   any    `json:"result,omitempty"`
}

// PolicyDecision is a lightweight alias/compat struct.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type PolicyDecision struct {
	DecisionID string    `json:"decision_id"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason"`
	BundleRev  string    `json:"bundle_rev"`
	Timestamp  time.Time `json:"timestamp"`

	// Deprecated / Backwards Compat
	Allow         bool   `json:"allow,omitempty"`
	PhenotypeHash string `json:"phenotype_hash,omitempty"` // now top-level
	ID            string `json:"id,omitempty"`
}

// PolicyRef is a reference to a policy artifacts.
type PolicyRef struct {
	URI  string `json:"uri"`
	Hash string `json:"hash"`
}

// VerdictPending is a transient verdict state with no canonical constant equivalent.
const VerdictPending = "PENDING"

// AuthorizedExecutionIntentSignatureV2 binds the full authority window and
// portable effect semantics. Unversioned legacy intents are never executable.
const AuthorizedExecutionIntentSignatureV2 = "authorized_execution_intent.v2"

// DecisionRecordSignatureV2 marks the HELM-303 decision preimage: ReasonCode
// replaces free-text Reason in the signed payload.
const DecisionRecordSignatureV2 = "decision_record.v2"

// DecisionRecordSignatureV3 binds Guardian-owned typed threat evidence when a
// decision contains it. Records without threat evidence remain on V2 so
// historical and ordinary decisions preserve their established preimage.
const DecisionRecordSignatureV3 = "decision_record.v3"

// DecisionRecordSignatureV4 is the current decision preimage. It retains the
// V2 reason digest and the V3 typed threat-evidence digest, then binds the
// evaluated authorization tuple and selected signature algorithm before any
// signature is created.
const DecisionRecordSignatureV4 = "decision_record.v4"

// ValidateDecisionAuthorityForUse restricts execution authority to the V4
// decision contract. Historical V2/V3 records remain verifiable as evidence,
// but lack the request and signer bindings needed to grant a new effect.
func ValidateDecisionAuthorityForUse(decision *DecisionRecord) error {
	if decision == nil {
		return fmt.Errorf("decision is required")
	}
	if decision.SignatureVersion != DecisionRecordSignatureV4 {
		return fmt.Errorf("execution authority requires %s, got %q", DecisionRecordSignatureV4, decision.SignatureVersion)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"subject ID", decision.SubjectID},
		{"action", decision.Action},
		{"resource", decision.Resource},
		{"signature type", decision.SignatureType},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("execution authority missing %s", field.name)
		}
	}
	return nil
}

// AuthorizedExecutionIntent represents a derived, signed intent to execute a specific effect.
// It decouples the "Permission" (Decision) from "Action" (Execution). (Sequence 8)
type AuthorizedExecutionIntent struct {
	ID               string               `json:"id"`                 // Derived Hash
	DecisionID       string               `json:"decision_id"`        // Link to permission
	EffectDigestHash string               `json:"effect_digest_hash"` // Bind to specific effect parameters
	EffectBinding    *EffectDigestBinding `json:"effect_binding,omitempty"`
	IdempotencyKey   string               `json:"idempotency_key"`
	IssuedAt         time.Time            `json:"issued_at"`
	ExpiresAt        time.Time            `json:"expires_at"`
	Signer           string               `json:"signer"`                      // Kernel Identity
	Signature        string               `json:"signature"`                   // Sig of the Intent
	SignatureType    string               `json:"signature_type"`              // Algorithm binding (e.g. "ed25519:key-id")
	SignatureVersion string               `json:"signature_version,omitempty"` // Signing-preimage contract
	AllowedTool      string               `json:"allowed_tool"`                // Constraint
	Taint            []string             `json:"taint,omitempty"`

	// Safe Deprecation Mode emergency authority bindings. These are populated
	// only after a prebuilt emergency capsule has passed continuity, hardware
	// quorum, attestation-result, and delegation validation.
	EmergencyActivationID        string `json:"emergency_activation_id,omitempty"`
	EmergencyDelegationSessionID string `json:"emergency_delegation_session_id,omitempty"`
	EmergencyScopeHash           string `json:"emergency_scope_hash,omitempty"`
}

// ValidateAt confirms that the signed execution-authority window is active.
func (i *AuthorizedExecutionIntent) ValidateAt(now time.Time) error {
	if i == nil {
		return fmt.Errorf("execution intent is required")
	}
	if i.IssuedAt.After(now) {
		return fmt.Errorf("execution intent is not active until %s", i.IssuedAt)
	}
	if i.ExpiresAt.IsZero() || !now.Before(i.ExpiresAt) {
		return fmt.Errorf("execution intent expired at %s", i.ExpiresAt)
	}
	return nil
}
