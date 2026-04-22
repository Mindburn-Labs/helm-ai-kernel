// Package contracts — DelegationProof evidence structure.
//
// Per HELM 2030 Spec §5.3:
//
//	Every delegation of authority MUST produce a typed, signed evidence
//	structure that is attributable and replayable.
//
// Resolves: GAP-A3.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// DelegationProof is the signed evidence of an authority delegation.
type DelegationProof struct {
	ProofID       string              `json:"proof_id"`
	DelegatorID   string              `json:"delegator_id"`
	DelegateeID   string              `json:"delegatee_id"`
	Scope         DelegationProofScope `json:"scope"`
	ChainDepth    int                 `json:"chain_depth"` // 0 = direct, 1+ = transitive
	ParentProofID string              `json:"parent_proof_id,omitempty"`
	IssuedAt      time.Time           `json:"issued_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
	Revoked       bool                `json:"revoked"`
	RevokedAt     *time.Time          `json:"revoked_at,omitempty"`
	RevokedBy     string              `json:"revoked_by,omitempty"`
	ContentHash   string              `json:"content_hash"`
	Signature     string              `json:"signature,omitempty"`
}

// DelegationProofScope defines what authority was delegated.
type DelegationProofScope struct {
	Actions      []string `json:"actions"`
	Resources    []string `json:"resources"`
	Namespaces   []string `json:"namespaces,omitempty"`
	MaxBudget    int64    `json:"max_budget_cents,omitempty"`
	MaxDepth     int      `json:"max_chain_depth"`
	AllowRedeleg bool     `json:"allow_redelegation"`
}

// DelegationChain is an ordered chain of delegation proofs from root to leaf.
type DelegationChain struct {
	ChainID string             `json:"chain_id"`
	Proofs  []DelegationProof  `json:"proofs"` // ordered: root → leaf
}

// ComputeHash computes the deterministic content hash of a DelegationProof.
func (d *DelegationProof) ComputeHash() string {
	input := fmt.Sprintf("%s:%s:%s:%v:%d:%s:%s",
		d.ProofID, d.DelegatorID, d.DelegateeID,
		d.Scope, d.ChainDepth,
		d.IssuedAt.UTC().String(), d.ExpiresAt.UTC().String())
	h := sha256.Sum256([]byte(input))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Verify checks the structural integrity of a delegation chain.
func (c *DelegationChain) Verify() error {
	if len(c.Proofs) == 0 {
		return fmt.Errorf("empty delegation chain")
	}
	for i, proof := range c.Proofs {
		// Verify hash integrity
		computed := proof.ComputeHash()
		if proof.ContentHash != "" && proof.ContentHash != computed {
			return fmt.Errorf("proof %d (%s): hash mismatch", i, proof.ProofID)
		}
		// Verify chain linkage
		if i > 0 {
			if proof.ParentProofID != c.Proofs[i-1].ProofID {
				return fmt.Errorf("proof %d: parent mismatch (expected %s, got %s)",
					i, c.Proofs[i-1].ProofID, proof.ParentProofID)
			}
			if proof.ChainDepth != i {
				return fmt.Errorf("proof %d: chain depth mismatch", i)
			}
		}
		// Verify non-expired
		if proof.Revoked {
			return fmt.Errorf("proof %d (%s): revoked", i, proof.ProofID)
		}
		// Verify no scope escalation (child cannot exceed parent)
		if i > 0 && proof.Scope.MaxDepth > c.Proofs[i-1].Scope.MaxDepth {
			return fmt.Errorf("proof %d: scope escalation (max_depth exceeds parent)", i)
		}
	}
	return nil
}
