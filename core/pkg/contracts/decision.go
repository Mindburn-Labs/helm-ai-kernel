// quantum_posture: execution-intent signature metadata is algorithm-neutral;
// protection depends on the configured classical, ML-DSA, or hybrid verifier.
package contracts

import (
	"fmt"
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
	// ThreatScan is typed evidence covered by the decision signature. InputContext
	// remains explainability metadata and is not itself a signature preimage.
	ThreatScan *ThreatScanRef `json:"threat_scan,omitempty"`
	// Session Risk Memory fields bind trajectory-level authorization state to the signed decision.
	TrajectoryRiskScore    float64 `json:"trajectory_risk_score,omitempty"`
	SessionCentroidHash    string  `json:"session_centroid_hash,omitempty"`
	RiskAccumulationWindow int     `json:"risk_accumulation_window,omitempty"`
	// RequirementSetHash links this decision to the specific Proof Requirement Graph rules satisfied.
	RequirementSetHash string    `json:"requirement_set_hash,omitempty"`
	Signature          string    `json:"signature"`
	SignatureType      string    `json:"signature_type"`
	Timestamp          time.Time `json:"timestamp"`

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
