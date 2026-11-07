// Package executor provides Merkle tree construction for EvidencePack.
// Per HELM Normative Addendum v1.5 Section C - EvidencePack Merkle Construction.
package executor

import ()

// MerkleProfileID is the profile identifier for Merkle-v1.
const MerkleProfileID = "merkle-v1"

// LeafDomainSeparator is the prefix for leaf hashes.
// Per Section C.2: leaf_hash = sha256(0x00 || leaf_canonical_bytes)
var LeafDomainSeparator = []byte{0x00}

// NodeDomainSeparator is the prefix for internal node hashes.
// Per Section C.3: node_hash = sha256(0x01 || left_hash || right_hash)
var NodeDomainSeparator = []byte{0x01}

// MerkleTree represents a complete Merkle tree.
type MerkleTree struct {
	// Root is the root hash of the tree.
	Root []byte `json:"root"`

	// Leaves contains the original data and their hashes.
	Leaves []MerkleLeaf `json:"leaves"`

	// Levels contains all tree levels for proof generation.
	// Level 0 is leaves, last level is root.
	Levels [][][]byte `json:"-"`
}

// MerkleLeaf represents a leaf in the Merkle tree.
type MerkleLeaf struct {
	Index    int    `json:"index"`
	Path     string `json:"path"` // JSON pointer path
	Hash     []byte `json:"hash"`
	Sealed   bool   `json:"sealed"` // Per Section C.8: Sealed leaves
	SealedAt int64  `json:"sealed_at,omitempty"`
}

// MerkleBuilder builds a Merkle tree from evidence components.
type MerkleBuilder struct {
	leaves []MerkleLeaf
}

// MerkleProof represents an inclusion proof.
// Per Section C.5: Inclusion proof structure.
type MerkleProof struct {
	LeafIndex int             `json:"leaf_index"`
	LeafPath  string          `json:"leaf_path"`
	LeafHash  string          `json:"leaf_hash"`
	Siblings  []MerkleSibling `json:"siblings"`
	Root      string          `json:"root"`
}

// MerkleSibling represents a sibling in the proof path.
type MerkleSibling struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// EvidenceView represents a derived view of an EvidencePack.
// Per Section C.9: EvidenceView derivation.
type EvidenceView struct {
	// ViewID uniquely identifies this view.
	ViewID string `json:"view_id"`

	// PackID references the source EvidencePack.
	PackID string `json:"pack_id"`

	// RootHash is the Merkle root of the full pack.
	RootHash string `json:"root_hash"`

	// IncludedPaths lists the paths included in this view.
	IncludedPaths []string `json:"included_paths"`

	// Proofs contains inclusion proofs for included leaves.
	Proofs []MerkleProof `json:"proofs"`

	// Data contains the actual data for included paths.
	Data map[string]any `json:"data"`
}
