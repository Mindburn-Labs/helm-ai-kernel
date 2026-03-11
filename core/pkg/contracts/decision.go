package contracts

import (
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
	ID            string `json:"id"`
	ProposalID    string `json:"proposal_id"`
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
	PolicyDecisionHash string `json:"policy_decision_hash,omitempty"` // SHA-256 of canonical decision

	StateCursor    string         `json:"state_cursor"`
	Snapshot       string         `json:"snapshot,omitempty"` // Content-Addressed Artifact Content
	EnvFingerprint string         `json:"env_fingerprint"`
	Verdict        string         `json:"verdict"`                 // Canonical: ALLOW, DENY, ESCALATE
	Reason         string         `json:"reason"`                  // Human-readable explanation
	ReasonCode     string         `json:"reason_code,omitempty"`   // Machine-readable registry code
	InputContext   map[string]any `json:"input_context,omitempty"` // For explainability
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

// AuthorizedExecutionIntent represents a derived, signed intent to execute a specific effect.
// It decouples the "Permission" (Decision) from "Action" (Execution). (Sequence 8)
type AuthorizedExecutionIntent struct {
	ID               string    `json:"id"`                 // Derived Hash
	DecisionID       string    `json:"decision_id"`        // Link to permission
	EffectDigestHash string    `json:"effect_digest_hash"` // Bind to specific effect parameters
	IdempotencyKey   string    `json:"idempotency_key"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Signer           string    `json:"signer"`       // Kernel Identity
	Signature        string    `json:"signature"`    // Sig of the Intent
	AllowedTool      string    `json:"allowed_tool"` // Constraint
}
