// Package aigp implements the AI Governance Proof (AIGP) Proof-Carrying Decision
// export format for HELM's ProofGraph.
//
// AIGP (https://open-aigp.org) is an open specification (Apache 2.0) for
// cryptographic proof of AI agent governance actions. Each PCD encodes:
//   - The governance action performed
//   - Cryptographic evidence (hashes, signatures)
//   - Selective Merkle inclusion proofs
//
// This enables interoperability with the broader AIGP ecosystem and
// satisfies the AIGP Four Tests Standard (4TS): Stoppable, Owned, Replayable, Escalatable.
package aigp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// PCDVersion is the AIGP PCD format version this implementation produces.
const PCDVersion = "aigp-pcd-v1"

// GovernanceActionType enumerates the types of governance actions in a PCD.
type GovernanceActionType string

const (
	ActionToolExecution GovernanceActionType = "tool_execution"
	ActionPolicyEval    GovernanceActionType = "policy_evaluation"
	ActionEscalation    GovernanceActionType = "escalation"
	ActionBudgetCheck   GovernanceActionType = "budget_check"
	ActionTrustEvent    GovernanceActionType = "trust_event"
	ActionCheckpoint    GovernanceActionType = "checkpoint"
)

// ProofCarryingDecision is the core AIGP export object.
// Each PCD is a self-contained, cryptographically verifiable record of a governance action.
type ProofCarryingDecision struct {
	// Version identifies the PCD format version.
	Version string `json:"version"`

	// ID is the unique identifier for this PCD (derived from the ProofGraph node hash).
	ID string `json:"id"`

	// Timestamp is when the governance action occurred.
	Timestamp time.Time `json:"timestamp"`

	// Action describes the governance action.
	Action GovernanceAction `json:"action"`

	// Evidence contains the cryptographic proof chain.
	Evidence CryptographicEvidence `json:"evidence"`

	// MerkleInclusion proves this PCD is part of the ProofGraph Merkle tree.
	MerkleInclusion *SelectiveMerkleProof `json:"merkle_inclusion,omitempty"`

	// Provenance links to the original ProofGraph data.
	Provenance PCDProvenance `json:"provenance"`

	// FourTests records compliance with the AIGP 4TS standard.
	FourTests FourTestsCompliance `json:"four_tests"`

	// PCDHash is the SHA-256 hash of this PCD for chaining.
	PCDHash string `json:"pcd_hash"`
}

// GovernanceAction describes what governance action was taken.
type GovernanceAction struct {
	// Type identifies the action category.
	Type GovernanceActionType `json:"type"`

	// Principal is the agent or user that triggered the action.
	Principal string `json:"principal"`

	// Decision is the governance outcome (e.g., "ALLOW", "DENY", "ESCALATE").
	Decision string `json:"decision"`

	// Reason is a human-readable explanation of the decision.
	Reason string `json:"reason,omitempty"`

	// Tool is the tool involved (for tool_execution actions).
	Tool string `json:"tool,omitempty"`

	// PolicyRef is the policy that was evaluated (for policy_evaluation actions).
	PolicyRef string `json:"policy_ref,omitempty"`

	// Metadata contains action-specific key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CryptographicEvidence contains the hash chain and signatures proving integrity.
type CryptographicEvidence struct {
	// GovernanceHash is the SHA-256 hash of the governance action for tamper evidence.
	GovernanceHash string `json:"governance_hash"`

	// NodeHash is the ProofGraph node hash this PCD was derived from.
	NodeHash string `json:"node_hash"`

	// ParentHashes links this PCD to its DAG parents.
	ParentHashes []string `json:"parent_hashes"`

	// Signature is the JWS ES256 signature over the governance hash (if available).
	Signature string `json:"signature,omitempty"`

	// HashAlgorithm identifies the hash algorithm used.
	HashAlgorithm string `json:"hash_algorithm"`

	// LamportClock is the logical timestamp from the ProofGraph.
	LamportClock uint64 `json:"lamport_clock"`
}

// SelectiveMerkleProof enables proving PCD membership without revealing siblings.
type SelectiveMerkleProof struct {
	// LeafHash is the hash of this PCD's leaf in the Merkle tree.
	LeafHash string `json:"leaf_hash"`

	// MerkleRoot is the root of the tree this proof is relative to.
	MerkleRoot string `json:"merkle_root"`

	// ProofPath is the list of sibling hashes needed to recompute the root.
	ProofPath []MerkleProofStep `json:"proof_path"`
}

// MerkleProofStep is a single step in a Merkle inclusion proof.
type MerkleProofStep struct {
	// Side indicates whether the sibling is on the "L" (left) or "R" (right).
	Side string `json:"side"`

	// Hash is the sibling hash at this level.
	Hash string `json:"hash"`
}

// PCDProvenance links the PCD back to the HELM ProofGraph.
type PCDProvenance struct {
	// Source identifies the HELM instance that produced this PCD.
	Source string `json:"source"`

	// ProofGraphVersion is the HELM standard version.
	ProofGraphVersion string `json:"proof_graph_version"`

	// NodeID is the ProofGraph node ID this PCD was derived from.
	NodeID string `json:"node_id"`

	// ExportTimestamp is when this PCD was exported.
	ExportTimestamp time.Time `json:"export_timestamp"`
}

// FourTestsCompliance records whether this governance action satisfies the AIGP 4TS.
type FourTestsCompliance struct {
	// Stoppable: Can authorized humans stop this action?
	Stoppable bool `json:"stoppable"`

	// Owned: Is there a named accountable role?
	Owned bool `json:"owned"`

	// Replayable: Can this action be replayed under inspection?
	Replayable bool `json:"replayable"`

	// Escalatable: Can this escalate to human control at policy boundaries?
	Escalatable bool `json:"escalatable"`

	// OwnerPrincipal is the named principal who owns this action.
	OwnerPrincipal string `json:"owner_principal,omitempty"`
}

// ComputePCDHash computes the deterministic SHA-256 hash of a PCD.
func (p *ProofCarryingDecision) ComputePCDHash() string {
	// Hash over the immutable fields (excluding PCDHash itself).
	data, err := json.Marshal(struct {
		Version    string                `json:"version"`
		ID         string                `json:"id"`
		Timestamp  time.Time             `json:"timestamp"`
		Action     GovernanceAction      `json:"action"`
		Evidence   CryptographicEvidence `json:"evidence"`
		Provenance PCDProvenance         `json:"provenance"`
	}{
		Version:    p.Version,
		ID:         p.ID,
		Timestamp:  p.Timestamp,
		Action:     p.Action,
		Evidence:   p.Evidence,
		Provenance: p.Provenance,
	})
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// nodeTypeToAction maps ProofGraph node types to AIGP governance action types.
func nodeTypeToAction(kind proofgraph.NodeType) GovernanceActionType {
	switch kind {
	case proofgraph.NodeTypeIntent:
		return ActionPolicyEval
	case proofgraph.NodeTypeAttestation:
		return ActionToolExecution
	case proofgraph.NodeTypeEffect:
		return ActionToolExecution
	case proofgraph.NodeTypeTrustEvent:
		return ActionTrustEvent
	case proofgraph.NodeTypeCheckpoint:
		return ActionCheckpoint
	case proofgraph.NodeTypeMergeDecision:
		return ActionPolicyEval
	default:
		return ActionToolExecution
	}
}
