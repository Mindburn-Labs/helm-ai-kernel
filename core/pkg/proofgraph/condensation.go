package proofgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// MerkleCondenser defines the interface for rolling up T0/T1 execution receipts
// into a verifiable Merkle Tree.
type MerkleCondenser interface {
	Condense(receipts []*contracts.Receipt) string
}

// DefaultMerkleCondenser is the standard implementation of MerkleCondenser.
type DefaultMerkleCondenser struct{}

// NewMerkleCondenser creates a new DefaultMerkleCondenser.
func NewMerkleCondenser() *DefaultMerkleCondenser {
	return &DefaultMerkleCondenser{}
}

// Condense builds a verifiable Merkle Tree of receipts and returns the root hash.
// The root hash serves as the canonical summary of the executed side-effects.
func (c *DefaultMerkleCondenser) Condense(receipts []*contracts.Receipt) string {
	if len(receipts) == 0 {
		return ""
	}

	var hashes []string
	for _, r := range receipts {
		// Use a deterministic payload string representation.
		// In a production environment, this would ideally use RFC 8785 JSON Canonicalization.
		payload := r.ReceiptID + "|" + r.DecisionID + "|" + r.EffectID + "|" + r.Status + "|" + r.PrevHash
		hash := sha256.Sum256([]byte(payload))
		hashes = append(hashes, hex.EncodeToString(hash[:]))
	}

	// Sort hashes to ensure deterministic tree structure for sets of receipts.
	sort.Strings(hashes)

	return c.buildTree(hashes)
}

func (c *DefaultMerkleCondenser) buildTree(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	var nextLevel []string
	for i := 0; i < len(hashes); i += 2 {
		left := hashes[i]
		right := left // Duplicate the last node if the level has an odd number of nodes
		if i+1 < len(hashes) {
			right = hashes[i+1]
		}
		
		combined := left + right
		hash := sha256.Sum256([]byte(combined))
		nextLevel = append(nextLevel, hex.EncodeToString(hash[:]))
	}

	return c.buildTree(nextLevel)
}
