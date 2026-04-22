package aigp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MerkleTree provides deterministic Merkle tree construction for selective
// disclosure of PCD sets per the AIGP specification.
type MerkleTree struct {
	leaves []string
	nodes  []string
}

// NewMerkleTree builds a Merkle tree from a set of PCD hashes.
func NewMerkleTree(pcdHashes []string) *MerkleTree {
	if len(pcdHashes) == 0 {
		return &MerkleTree{}
	}

	// Pad to power of 2.
	padded := make([]string, len(pcdHashes))
	copy(padded, pcdHashes)
	for len(padded)&(len(padded)-1) != 0 {
		padded = append(padded, padded[len(padded)-1]) // duplicate last leaf
	}

	tree := &MerkleTree{leaves: padded}
	tree.nodes = tree.build(padded)
	return tree
}

// Root returns the Merkle root hash.
func (t *MerkleTree) Root() string {
	if len(t.nodes) == 0 {
		return ""
	}
	return t.nodes[len(t.nodes)-1]
}

// InclusionProof generates a Merkle proof for a specific leaf index.
// The proof consists of sibling hashes needed to reconstruct the root.
func (t *MerkleTree) InclusionProof(leafIndex int) (*SelectiveProof, error) {
	if leafIndex < 0 || leafIndex >= len(t.leaves) {
		return nil, fmt.Errorf("aigp: leaf index %d out of range [0, %d)", leafIndex, len(t.leaves))
	}

	proof := &SelectiveProof{
		LeafIndex: leafIndex,
		LeafHash:  t.leaves[leafIndex],
		Root:      t.Root(),
	}

	// Walk up the tree collecting sibling hashes.
	n := len(t.leaves)
	offset := 0
	idx := leafIndex

	for n > 1 {
		if idx%2 == 0 {
			// Sibling is to the right
			if idx+1 < n {
				proof.Siblings = append(proof.Siblings, SiblingNode{
					Hash:     t.nodes[offset+idx+1],
					Position: "right",
				})
			}
		} else {
			// Sibling is to the left
			proof.Siblings = append(proof.Siblings, SiblingNode{
				Hash:     t.nodes[offset+idx-1],
				Position: "left",
			})
		}
		offset += n
		idx /= 2
		n /= 2
	}

	return proof, nil
}

// VerifyInclusion checks that a proof is valid against the given root.
func VerifyInclusion(proof *SelectiveProof) bool {
	hash := proof.LeafHash
	for _, sibling := range proof.Siblings {
		if sibling.Position == "left" {
			hash = hashPair(sibling.Hash, hash)
		} else {
			hash = hashPair(hash, sibling.Hash)
		}
	}
	return hash == proof.Root
}

// SelectiveProof is a Merkle inclusion proof for selective PCD disclosure.
type SelectiveProof struct {
	LeafIndex int           `json:"leaf_index"`
	LeafHash  string        `json:"leaf_hash"`
	Root      string        `json:"root"`
	Siblings  []SiblingNode `json:"siblings"`
}

// SiblingNode is a node in the Merkle proof path.
type SiblingNode struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

func (t *MerkleTree) build(leaves []string) []string {
	allNodes := make([]string, 0, 2*len(leaves))
	allNodes = append(allNodes, leaves...)

	current := leaves
	for len(current) > 1 {
		var next []string
		for i := 0; i < len(current); i += 2 {
			h := hashPair(current[i], current[i+1])
			next = append(next, h)
		}
		allNodes = append(allNodes, next...)
		current = next
	}
	return allNodes
}

func hashPair(a, b string) string {
	combined := a + b
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}
