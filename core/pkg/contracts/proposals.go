package contracts

import "time"

// Kind defines the category of change.
type Kind string

// Kind constants.
const (
	KindSpend      Kind = "SPEND"
	KindDeploy     Kind = "DEPLOY"
	KindAccess     Kind = "ACCESS"
	KindLawChange  Kind = "LAW_CHANGE"
	KindAutophagy  Kind = "AUTOPHAGY"
	KindActivation Kind = "RAIL_ACTIVATION"
)

// Status defines the lifecycle of a proposal.
type Status string

// Status constants.
const (
	StatusDraft       Status = "DRAFT"
	StatusSubmitted   Status = "SUBMITTED"
	StatusUnderReview Status = "UNDER_REVIEW"
	StatusVerdicted   Status = "VERDICTED"
	StatusApplied     Status = "APPLIED"
	StatusVerified    Status = "VERIFIED"
	StatusClosed      Status = "CLOSED"
	StatusRejected    Status = "REJECTED"
	StatusExpired     Status = "EXPIRED"
)

// Intent captures the human meaning of the change.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Intent struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Type        string         `json:"type,omitempty"`     // e.g. "escalation", "spend"
	Metadata    map[string]any `json:"metadata,omitempty"` // Context
	RequestedBy string         `json:"requested_by"`       // Principal ID
	CreatedAt   time.Time      `json:"created_at"`         // Metadata
}

// Scope defines the impact radius.
type Scope struct {
	Domains     []string `json:"domains,omitempty"`
	Systems     []string `json:"systems,omitempty"`
	BlastRadius string   `json:"blast_radius"` // LOW, MEDIUM, HIGH
}

// Invariant represents a hard constraint that must hold true.
type Invariant struct {
	Type        string `json:"type"`        // e.g., "MAX_AMOUNT"
	Description string `json:"description"` // e.g., "must not exceed 1000 USD"
	Param       string `json:"param"`       // e.g., "1000"
}

// ActionPlanRef points to the execution plan.
type ActionPlanRef struct {
	PlanHash    string `json:"plan_hash"`
	PlanVersion string `json:"plan_version"`
	URI         string `json:"uri,omitempty"`
}

// Provenance captures origin and tool context.
type Provenance struct {
	RepoCommit      string `json:"repo_commit"`
	ToolFingerprint string `json:"tool_fingerprint"`
}

// Signature binds an entity to the proposal.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Signature struct {
	SignerID  string    `json:"signer_id"`
	Role      string    `json:"role"` // PROPOSER, NOTARY, REVIEWER
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// Proposal is the sovereign envelope for change.
type Proposal struct {
	ProposalID string `json:"proposal_id"`

	Kind       Kind        `json:"kind"`
	Intent     Intent      `json:"intent"`
	Scope      Scope       `json:"scope"`
	Invariants []Invariant `json:"invariants,omitempty"`

	Plan     ActionPlanRef `json:"plan"`
	Rollback string        `json:"rollback"` // Simplification: Strategy description or ref

	Proofs map[ProofType]ProofPack `json:"proofs,omitempty"`

	Provenance Provenance  `json:"provenance"`
	Signatures []Signature `json:"signatures,omitempty"`

	Status Status `json:"status"`
}
