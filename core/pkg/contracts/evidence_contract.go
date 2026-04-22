// Package contracts defines the EvidenceContract — per-action-class evidence
// requirements enforced at the PDP.
//
// Per HELM 2030 Spec — Proof-carrying operations:
//   - Every action class has defined evidence requirements
//   - Evidence is verified before or after execution depending on contract
//   - Evidence contracts are versioned and auditable
package contracts

import "time"

// EvidenceContract binds an action class to its evidence requirements.
type EvidenceContract struct {
	// ContractID is the unique identifier.
	ContractID string `json:"contract_id"`

	// ActionClass is the effect class or specific type this contract applies to.
	ActionClass string `json:"action_class"`

	// Requirements lists what evidence must be produced.
	Requirements []EvidenceSpec `json:"requirements"`

	// Version for auditability.
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EvidenceSpec specifies a single evidence requirement.
type EvidenceSpec struct {
	// EvidenceType is the kind of evidence.
	// Values: receipt, hash_proof, dual_attestation, external_verification, replay_proof
	EvidenceType string `json:"evidence_type"`

	// When specifies timing relative to execution.
	// Values: "before", "after", "both"
	When string `json:"when"`

	// IssuerConstraint optionally constrains who may produce the evidence.
	IssuerConstraint string `json:"issuer_constraint,omitempty"`

	// Required indicates if this evidence is mandatory or optional.
	Required bool `json:"required"`

	// Description explains the purpose of this evidence.
	Description string `json:"description,omitempty"`
}

// EvidenceSubmission is evidence produced for an action.
type EvidenceSubmission struct {
	SubmissionID string    `json:"submission_id"`
	ContractID   string    `json:"contract_id"`
	ActionClass  string    `json:"action_class"`
	EvidenceType string    `json:"evidence_type"`
	ContentHash  string    `json:"content_hash"`
	IssuerID     string    `json:"issuer_id"`
	SubmittedAt  time.Time `json:"submitted_at"`
	Verified     bool      `json:"verified"`
}

// EvidenceVerdict is the result of verifying evidence against a contract.
type EvidenceVerdict struct {
	Satisfied  bool                 `json:"satisfied"`
	Missing    []EvidenceSpec       `json:"missing,omitempty"`
	Verified   []EvidenceSubmission `json:"verified,omitempty"`
	ContractID string               `json:"contract_id"`
	VerifiedAt time.Time            `json:"verified_at"`
}

// EvidenceContractManifest is the versioned collection of all evidence contracts.
type EvidenceContractManifest struct {
	Version     string             `json:"version"`
	ContentHash string             `json:"content_hash"`
	Contracts   []EvidenceContract `json:"contracts"`
	UpdatedAt   time.Time          `json:"updated_at"`
}
