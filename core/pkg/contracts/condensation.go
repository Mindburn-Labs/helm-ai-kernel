package contracts

import "time"

// ProofCondensation represents the configuration and state of proof
// condensation for a session or workflow.
// Per ARCHITECTURE.md §5.2: Proof Condensation.
type ProofCondensation struct {
	// CheckpointInterval defines how often (in receipt count) checkpoints
	// are created. At each checkpoint, the kernel computes an incremental
	// Merkle root over accumulated receipts.
	CheckpointInterval int `json:"checkpoint_interval"`

	// RetentionPolicy maps risk tiers to retention behavior.
	RetentionPolicy []CondensationTierPolicy `json:"retention_policy"`
}

// RiskTier classifies the risk level of a receipt for condensation purposes.
type RiskTier string

const (
	// RiskTierLow covers T0-T1 effects (informational, low-impact).
	// Condensed to Merkle inclusion proofs after checkpoint.
	RiskTierLow RiskTier = "LOW"

	// RiskTierMedium covers T2 effects (moderate impact).
	// Full receipts retained, periodic Merkle checkpoints.
	RiskTierMedium RiskTier = "MEDIUM"

	// RiskTierHigh covers T3+ effects (high impact, irreversible).
	// Full receipt chain, no condensation, anchored to transparency log.
	RiskTierHigh RiskTier = "HIGH"
)

// CondensationTierPolicy defines retention behavior for a risk tier.
type CondensationTierPolicy struct {
	Tier                RiskTier `json:"tier"`
	RetainFullReceipts  bool     `json:"retain_full_receipts"`
	CondenseAfterWindow bool     `json:"condense_after_window"`
	AnchorToExternal    bool     `json:"anchor_to_external"`
}

// CondensationCheckpoint represents a periodic checkpoint in the
// proof condensation system. After checkpoint, low-risk receipts
// may be replaced by their Merkle inclusion proofs.
type CondensationCheckpoint struct {
	// CheckpointID uniquely identifies this checkpoint.
	CheckpointID string `json:"checkpoint_id"`

	// MerkleRoot is the incremental Merkle root over accumulated receipts.
	MerkleRoot string `json:"merkle_root"`

	// ReceiptCount is the number of receipts included in this checkpoint.
	ReceiptCount int `json:"receipt_count"`

	// FirstReceiptID is the ID of the first receipt in this checkpoint window.
	FirstReceiptID string `json:"first_receipt_id"`

	// LastReceiptID is the ID of the last receipt in this checkpoint window.
	LastReceiptID string `json:"last_receipt_id"`

	// LamportClock is the Lamport clock value at checkpoint time.
	LamportClock int64 `json:"lamport_clock"`

	// CreatedAt is when this checkpoint was created.
	CreatedAt time.Time `json:"created_at"`

	// Signature is the Ed25519 signature over the checkpoint.
	Signature string `json:"signature"`
}

// CondensedReceipt represents a receipt that has been condensed to
// its Merkle inclusion proof. Sufficient for audit verification but
// significantly smaller than the full receipt.
type CondensedReceipt struct {
	// ReceiptID is the original receipt ID.
	ReceiptID string `json:"receipt_id"`

	// CheckpointID references the checkpoint this receipt was condensed in.
	CheckpointID string `json:"checkpoint_id"`

	// InclusionProof is the Merkle inclusion proof for this receipt
	// against the checkpoint's MerkleRoot.
	InclusionProof CondensationInclusionProof `json:"inclusion_proof"`
}

// CondensationInclusionProof proves a receipt was included in a checkpoint.
type CondensationInclusionProof struct {
	// LeafHash is the hash of the original receipt.
	LeafHash string `json:"leaf_hash"`

	// Siblings are the sibling hashes in the proof path.
	Siblings []string `json:"siblings"`

	// Positions indicate whether each sibling is left or right.
	Positions []string `json:"positions"`

	// Root is the Merkle root this proof verifies against.
	Root string `json:"root"`
}

// DefaultCondensationPolicy returns the default proof condensation policy
// with risk-tiered retention per ARCHITECTURE.md §5.2.
func DefaultCondensationPolicy() ProofCondensation {
	return ProofCondensation{
		CheckpointInterval: 100,
		RetentionPolicy: []CondensationTierPolicy{
			{Tier: RiskTierLow, RetainFullReceipts: false, CondenseAfterWindow: true, AnchorToExternal: false},
			{Tier: RiskTierMedium, RetainFullReceipts: true, CondenseAfterWindow: true, AnchorToExternal: false},
			{Tier: RiskTierHigh, RetainFullReceipts: true, CondenseAfterWindow: false, AnchorToExternal: true},
		},
	}
}
