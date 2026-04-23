package contracts

import "time"

// GenesisApprovalBinding represents the four-hash cryptographic binding
// required by the ORG_GENESIS_APPROVAL ceremony in the Verified Genesis Loop.
// Per ARCHITECTURE.md §3 and UCS v1.2.
//
//nolint:govet // fieldalignment: struct layout matches ARCHITECTURE.md hash order
type GenesisApprovalBinding struct {
	// PolicyGenesisHash is the SHA-256 of the JCS-canonicalized proposed policy genesis state.
	PolicyGenesisHash string `json:"policy_genesis_hash"`

	// MirrorTextHash is the SHA-256 of the Deterministic Semantic Mirror
	// shown to the approver. UCS v1.2 canonical name.
	MirrorTextHash string `json:"mirror_text_hash"`

	// ImpactReportHash is the SHA-256 of the PhenotypeDiff + ConfluenceProof
	// wargaming output.
	ImpactReportHash string `json:"impact_report_hash"`

	// P0CeilingHash is the SHA-256 of the active P0 ceiling set at approval time.
	P0CeilingHash string `json:"p0_ceiling_hash"`
}

// GenesisApprovalRequest is the canonical request structure for the
// GENESIS_APPROVAL ceremony. Extends v1 CeremonyRequest with the
// four-hash binding required by UCS v1.2 for activation gating.
type GenesisApprovalRequest struct {
	// Binding contains the four cryptographic hashes that bind this
	// approval to a specific genome, mirror, impact report, and P0 ceiling.
	Binding GenesisApprovalBinding `json:"binding"`

	// ChallengeHash is derived from all four binding hashes.
	// The approver signs this to produce a deliberate confirmation.
	ChallengeHash string `json:"challenge_hash"`

	// Quorum is the number of approvers required. 0 = single approver.
	Quorum int `json:"quorum"`

	// TimelockDuration is the minimum time that must elapse before
	// the approval activates.
	TimelockDuration time.Duration `json:"timelock_duration"`

	// RateLimitWindow prevents rapid successive genome mutations.
	// If non-zero, no new genesis approval may be submitted within
	// this window after the previous activation.
	RateLimitWindow time.Duration `json:"rate_limit_window,omitempty"`

	// EmergencyOverride indicates this is an emergency bypass that
	// generates elevated-risk receipts and mandatory post-hoc review.
	EmergencyOverride bool `json:"emergency_override"`

	// ApproverKeyIDs is the list of Ed25519 key IDs that signed this approval.
	ApproverKeyIDs []string `json:"approver_key_ids"`

	// Signatures is the list of Ed25519 signatures from each approver,
	// each over the ChallengeHash.
	Signatures []string `json:"signatures"`

	// SubmittedAt is the time the ceremony request was submitted.
	SubmittedAt time.Time `json:"submitted_at"`
}

// GenesisApprovalResult is the outcome of VGL ceremony validation.
type GenesisApprovalResult struct {
	Valid          bool   `json:"valid"`
	Reason         string `json:"reason,omitempty"`
	ActivatesAt    int64  `json:"activates_at,omitempty"`
	RequiresReview bool   `json:"requires_review,omitempty"`
	ElevatedRisk   bool   `json:"elevated_risk,omitempty"`
}
