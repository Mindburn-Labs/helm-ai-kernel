// Package contracts defines the Autonomy Envelope — the signed, versioned
// runtime boundary contract that bounds every autonomous run.
//
// Per HELM 2030 Spec Section 2 — Autonomy Envelope:
//   - Signed, versioned, and attached to every autonomous run
//   - Declares jurisdiction scope, data handling, allowed effects, budgets,
//     required evidence, and escalation policy
//   - "Autonomy default" means: envelope pre-approved, continuously monitored,
//     and continuously enforced; anything outside becomes an exception
package contracts

import "time"

// AutonomyEnvelope is the first-class runtime contract that bounds an autonomous run.
// It must be signed, versioned, and validated by the kernel before any effects execute.
type AutonomyEnvelope struct {
	// Identity
	EnvelopeID    string `json:"envelope_id"`
	Version       string `json:"version"`        // Semantic version of this envelope definition
	FormatVersion string `json:"format_version"` // Schema format version, currently "1.0.0"

	// Validity window
	ValidFrom  time.Time `json:"valid_from,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitempty"`

	// Tenant scope
	TenantID string `json:"tenant_id,omitempty"`

	// Core constraints
	JurisdictionScope JurisdictionConstraint `json:"jurisdiction_scope"`
	DataHandling      DataHandlingRules      `json:"data_handling"`
	AllowedEffects    []EffectClassAllowlist `json:"allowed_effects"`
	Budgets           EnvelopeBudgets        `json:"budgets"`
	RequiredEvidence  []EvidenceRequirement  `json:"required_evidence"`
	EscalationPolicy  EscalationRules        `json:"escalation_policy"`

	// Cryptographic attestation
	Attestation EnvelopeAttestation `json:"attestation"`
}

// JurisdictionConstraint defines where a run is legally allowed to operate.
type JurisdictionConstraint struct {
	// AllowedJurisdictions is the set of ISO codes where this run may operate.
	AllowedJurisdictions []string `json:"allowed_jurisdictions"`

	// RegulatoryMode controls how strictly compliance rules are enforced.
	// Values: "strict", "permissive", "audit_only"
	RegulatoryMode string `json:"regulatory_mode"`

	// DataResidencyRegions constrains where data may reside.
	DataResidencyRegions []string `json:"data_residency_regions,omitempty"`

	// ProhibitedJurisdictions are explicitly denied.
	ProhibitedJurisdictions []string `json:"prohibited_jurisdictions,omitempty"`
}

// DataHandlingRules govern data classification, residency, and redaction.
type DataHandlingRules struct {
	// MaxClassification is the highest data classification this run may handle autonomously.
	// Values: "public", "internal", "confidential", "restricted"
	MaxClassification string `json:"max_classification"`

	// RedactionPolicy controls redaction applied to outputs and logs.
	// Values: "none", "pii_only", "strict"
	RedactionPolicy string `json:"redaction_policy"`

	// TransferConstraints define cross-border data transfer rules.
	TransferConstraints []DataTransferConstraint `json:"transfer_constraints,omitempty"`
}

// DataTransferConstraint governs cross-border data movement.
type DataTransferConstraint struct {
	FromRegion         string `json:"from_region"`
	ToRegion           string `json:"to_region"`
	Allowed            bool   `json:"allowed"`
	RequiresEncryption bool   `json:"requires_encryption,omitempty"`
}

// EffectClassAllowlist declares which effect classes are allowed autonomously.
type EffectClassAllowlist struct {
	// EffectClass is the HELM effect class: E0, E1, E2, E3, E4
	EffectClass string `json:"effect_class"`

	// Allowed indicates whether this class is permitted autonomously.
	Allowed bool `json:"allowed"`

	// AllowedTypes optionally restricts to specific effect type IDs.
	AllowedTypes []string `json:"allowed_types,omitempty"`

	// MaxPerRun caps effects of this class per run.
	MaxPerRun int `json:"max_per_run,omitempty"`

	// RequiresApprovalAbove triggers escalation when this count is exceeded.
	RequiresApprovalAbove int `json:"requires_approval_above,omitempty"`
}

// EnvelopeBudgets defines economic and operational ceilings for a run.
type EnvelopeBudgets struct {
	// CostCeilingCents is the maximum monetary cost in cents.
	CostCeilingCents int64 `json:"cost_ceiling_cents"`

	// TimeCeilingSeconds is the maximum wall-clock time.
	TimeCeilingSeconds int64 `json:"time_ceiling_seconds"`

	// ToolCallCap is the maximum number of tool calls.
	ToolCallCap int64 `json:"tool_call_cap"`

	// RateLimits are per-resource rate limits.
	RateLimits []RateLimit `json:"rate_limits,omitempty"`

	// BlastRadius is the maximum allowed blast radius for any single effect.
	// Values: "single_record", "dataset", "system_wide"
	BlastRadius string `json:"blast_radius,omitempty"`

	// ComputeUnitsCap caps compute units (LLM tokens, GPU seconds, etc.).
	ComputeUnitsCap int64 `json:"compute_units_cap,omitempty"`
}

// RateLimit constrains per-resource throughput.
type RateLimit struct {
	Resource     string `json:"resource"`
	MaxPerMinute int    `json:"max_per_minute"`
}

// EvidenceRequirement specifies what must be proven per action class.
type EvidenceRequirement struct {
	// ActionClass is the effect class or type this requirement applies to.
	ActionClass string `json:"action_class"`

	// EvidenceType is the kind of evidence required.
	// Values: "receipt", "hash_proof", "dual_attestation", "external_verification", "replay_proof"
	EvidenceType string `json:"evidence_type"`

	// When specifies timing relative to execution.
	// Values: "before", "after", "both"
	When string `json:"when"`

	// IssuerConstraint optionally constrains who may produce the evidence.
	IssuerConstraint string `json:"issuer_constraint,omitempty"`
}

// EscalationRules define when and how judgment-required acts are escalated.
type EscalationRules struct {
	// DefaultMode is the default execution mode.
	// Values: "autonomous", "supervised", "manual"
	DefaultMode string `json:"default_mode"`

	// EscalationTriggers define conditions that require escalation.
	EscalationTriggers []EscalationTrigger `json:"escalation_triggers,omitempty"`

	// JudgmentTaxonomy classifies action categories.
	JudgmentTaxonomy []JudgmentClassification `json:"judgment_taxonomy,omitempty"`
}

// EscalationTrigger defines a condition that triggers judgment-required escalation.
type EscalationTrigger struct {
	// Condition is a CEL expression for when to escalate.
	Condition string `json:"condition"`

	// Action specifies what to do when condition matches.
	// Values: "require_approval", "pause_and_notify", "abort"
	Action string `json:"action"`

	// Approvers lists required approver roles or IDs.
	Approvers []string `json:"approvers,omitempty"`

	// Quorum is the number of approvals needed.
	Quorum int `json:"quorum,omitempty"`

	// TimeoutSeconds is the escalation timeout.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// JudgmentClassification categorizes an action as autonomous or judgment-required.
type JudgmentClassification struct {
	// Category is the action category name.
	Category string `json:"category"`

	// Classification is either "autonomous" or "judgment_required".
	Classification string `json:"classification"`
}

// EnvelopeAttestation provides cryptographic binding for the envelope.
type EnvelopeAttestation struct {
	// ContentHash is the SHA-256 hash of envelope content (excluding attestation).
	ContentHash string `json:"content_hash"`

	// Signature is the cryptographic signature of the content_hash.
	Signature string `json:"signature,omitempty"`

	// SignerID identifies who signed the envelope.
	SignerID string `json:"signer_id,omitempty"`

	// SignedAt is when the envelope was signed.
	SignedAt time.Time `json:"signed_at,omitempty"`

	// Algorithm is the signature algorithm used.
	// Values: "ED25519", "ECDSA-P256", "RSA-PSS-2048"
	Algorithm string `json:"algorithm,omitempty"`
}

// Regulatory mode constants.
const (
	RegulatoryModeStrict     = "strict"
	RegulatoryModePermissive = "permissive"
	RegulatoryModeAuditOnly  = "audit_only"
)

// Data classification constants.
const (
	DataClassPublic       = "public"
	DataClassInternal     = "internal"
	DataClassConfidential = "confidential"
	DataClassRestricted   = "restricted"
)

// Escalation default mode constants.
const (
	EscalationModeAutonomous = "autonomous"
	EscalationModeSupervised = "supervised"
	EscalationModeManual     = "manual"
)

// Escalation action constants.
const (
	EscalationActionRequireApproval = "require_approval"
	EscalationActionPauseAndNotify  = "pause_and_notify"
	EscalationActionAbort           = "abort"
)

// Judgment classification constants.
const (
	JudgmentAutonomous = "autonomous"
	JudgmentRequired   = "judgment_required"
)

// Evidence type constants.
const (
	EvidenceTypeReceipt              = "receipt"
	EvidenceTypeHashProof            = "hash_proof"
	EvidenceTypeDualAttestation      = "dual_attestation"
	EvidenceTypeExternalVerification = "external_verification"
	EvidenceTypeReplayProof          = "replay_proof"
)

// Blast radius constants.
const (
	BlastRadiusSingleRecord = "single_record"
	BlastRadiusDataset      = "dataset"
	BlastRadiusSystemWide   = "system_wide"
)
