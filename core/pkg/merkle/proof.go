package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type InclusionProof struct {
	LeafPath   string      `json:"leaf_path"`
	LeafHash   string      `json:"leaf_hash"`
	MerkleRoot string      `json:"merkle_root"`
	ProofPath  []ProofStep `json:"proof_path"`
}

type ProofStep struct {
	Side        string `json:"side"` // "L" or "R"
	SiblingHash string `json:"sibling_hash"`
}

// VerifyInclusionProof verifies that a leaf is part of the Merkle tree.
func VerifyInclusionProof(proof InclusionProof, expectedRoot string) bool {
	// If expectedRoot is provided, match it against proof.MerkleRoot?
	// Spec says: "currentHash == expectedRoot".
	// The proof object contains MerkleRoot, but caller typically provides trusted root.

	if expectedRoot != "" && proof.MerkleRoot != expectedRoot {
		return false
	}

	currentHash := proof.LeafHash

	for _, step := range proof.ProofPath {
		var combined []byte
		// node_hash = SHA256("helm:evidence:node:v1\0" || left_hash || right_hash)
		// Prefix
		combined = append(combined, []byte("helm:evidence:node:v1\x00")...)

		if step.Side == "L" {
			// Sibling is Left, Current is Right
			combined = append(combined, hexToBytes(step.SiblingHash)...)
			combined = append(combined, hexToBytes(currentHash)...)
		} else {
			// Sibling is Right, Current is Left
			combined = append(combined, hexToBytes(currentHash)...)
			combined = append(combined, hexToBytes(step.SiblingHash)...)
		}

		hash := sha256.Sum256(combined)
		currentHash = hex.EncodeToString(hash[:])
	}

	// Final check: currentHash should match proof.MerkleRoot (and expectedRoot if checked above)
	return strings.EqualFold(currentHash, proof.MerkleRoot)
}
