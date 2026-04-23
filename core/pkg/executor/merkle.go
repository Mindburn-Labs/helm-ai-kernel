// Package executor provides Merkle tree construction for EvidencePack.
// Per HELM Normative Addendum v1.5 Section C - EvidencePack Merkle Construction.
package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

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

// NewMerkleBuilder creates a new Merkle builder.
func NewMerkleBuilder() *MerkleBuilder {
	return &MerkleBuilder{
		leaves: make([]MerkleLeaf, 0),
	}
}

// AddLeaf adds a leaf to the tree.
// Per Section C.2: Leaf derivation from canonical JSON.
func (b *MerkleBuilder) AddLeaf(path string, value any, sealed bool) error {
	// Serialize to canonical JSON (sorted keys)
	canonical, err := canonicalJSON(value)
	if err != nil {
		return fmt.Errorf("merkle: failed to serialize leaf at %s: %w", path, err)
	}

	// Compute leaf hash with domain separator
	hash := computeLeafHash(canonical)

	leaf := MerkleLeaf{
		Index:  len(b.leaves),
		Path:   path,
		Hash:   hash,
		Sealed: sealed,
	}

	b.leaves = append(b.leaves, leaf)
	return nil
}

// AddLeafBytes adds a leaf from raw bytes.
func (b *MerkleBuilder) AddLeafBytes(path string, data []byte, sealed bool) {
	hash := computeLeafHash(data)

	leaf := MerkleLeaf{
		Index:  len(b.leaves),
		Path:   path,
		Hash:   hash,
		Sealed: sealed,
	}

	b.leaves = append(b.leaves, leaf)
}

// computeLeafHash computes the hash for a leaf.
// Per Section C.2: leaf_hash = sha256(0x00 || data)
func computeLeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write(LeafDomainSeparator)
	h.Write(data)
	return h.Sum(nil)
}

// computeNodeHash computes the hash for an internal node.
// Per Section C.3: node_hash = sha256(0x01 || left || right)
func computeNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(NodeDomainSeparator)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Build constructs the Merkle tree and returns the root.
// Per Section C.4: Tree construction algorithm.
func (b *MerkleBuilder) Build() (*MerkleTree, error) {
	if len(b.leaves) == 0 {
		return nil, fmt.Errorf("merkle: cannot build tree with no leaves")
	}

	// Extract leaf hashes
	level := make([][]byte, len(b.leaves))
	for i, leaf := range b.leaves {
		level[i] = leaf.Hash
	}

	levels := [][][]byte{level}

	// Build levels until we have a single root
	for len(level) > 1 {
		nextLevel := make([][]byte, 0, (len(level)+1)/2)

		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				// Two nodes - combine them
				hash := computeNodeHash(level[i], level[i+1])
				nextLevel = append(nextLevel, hash)
			} else {
				// Odd node - promote without hashing (unbalanced tree)
				// Per Section C.4: For odd counts, promote the last hash.
				nextLevel = append(nextLevel, level[i])
			}
		}

		level = nextLevel
		levels = append(levels, level)
	}

	return &MerkleTree{
		Root:   level[0],
		Leaves: b.leaves,
		Levels: levels,
	}, nil
}

// RootHex returns the root hash as a hex string.
func (t *MerkleTree) RootHex() string {
	return hex.EncodeToString(t.Root)
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

// GenerateProof generates an inclusion proof for a leaf.
// Per Section C.5: Proof generation algorithm.
func (t *MerkleTree) GenerateProof(leafIndex int) (*MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= len(t.Leaves) {
		return nil, fmt.Errorf("merkle: leaf index %d out of range [0, %d)", leafIndex, len(t.Leaves))
	}

	proof := &MerkleProof{
		LeafIndex: leafIndex,
		LeafPath:  t.Leaves[leafIndex].Path,
		LeafHash:  hex.EncodeToString(t.Leaves[leafIndex].Hash),
		Siblings:  make([]MerkleSibling, 0),
		Root:      t.RootHex(),
	}

	idx := leafIndex
	for levelNum := 0; levelNum < len(t.Levels)-1; levelNum++ {
		level := t.Levels[levelNum]

		// Determine sibling position
		var siblingIdx int
		var position string

		if idx%2 == 0 {
			siblingIdx = idx + 1
			position = "right"
		} else {
			siblingIdx = idx - 1
			position = "left"
		}

		// Add sibling to proof if it exists
		if siblingIdx < len(level) {
			proof.Siblings = append(proof.Siblings, MerkleSibling{
				Hash:     hex.EncodeToString(level[siblingIdx]),
				Position: position,
			})
		}

		// Move to parent index
		idx = idx / 2
	}

	return proof, nil
}

// VerifyProof verifies a Merkle inclusion proof.
// Per Section C.6: Proof verification algorithm.
func VerifyProof(proof *MerkleProof) (bool, error) {
	leafHash, err := hex.DecodeString(proof.LeafHash)
	if err != nil {
		return false, fmt.Errorf("merkle: invalid leaf hash: %w", err)
	}

	currentHash := leafHash

	for _, sibling := range proof.Siblings {
		siblingHash, err := hex.DecodeString(sibling.Hash)
		if err != nil {
			return false, fmt.Errorf("merkle: invalid sibling hash: %w", err)
		}

		if sibling.Position == "left" {
			currentHash = computeNodeHash(siblingHash, currentHash)
		} else {
			currentHash = computeNodeHash(currentHash, siblingHash)
		}
	}

	expectedRoot, err := hex.DecodeString(proof.Root)
	if err != nil {
		return false, fmt.Errorf("merkle: invalid root hash: %w", err)
	}

	return bytes.Equal(currentHash, expectedRoot), nil
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

// DeriveView creates an EvidenceView with only specified paths.
// Per Section C.9: View derivation for minimal disclosure.
func (t *MerkleTree) DeriveView(viewID, packID string, paths []string, getData func(path string) (any, error)) (*EvidenceView, error) {
	view := &EvidenceView{
		ViewID:        viewID,
		PackID:        packID,
		RootHash:      t.RootHex(),
		IncludedPaths: paths,
		Proofs:        make([]MerkleProof, 0, len(paths)),
		Data:          make(map[string]any),
	}

	// Build path-to-index lookup
	pathIndex := make(map[string]int)
	for _, leaf := range t.Leaves {
		pathIndex[leaf.Path] = leaf.Index
	}

	// Generate proofs for requested paths
	for _, path := range paths {
		idx, exists := pathIndex[path]
		if !exists {
			return nil, fmt.Errorf("merkle: path %q not found in tree", path)
		}

		proof, err := t.GenerateProof(idx)
		if err != nil {
			return nil, err
		}
		view.Proofs = append(view.Proofs, *proof)

		// Get data for this path
		if getData != nil {
			data, err := getData(path)
			if err != nil {
				return nil, fmt.Errorf("merkle: failed to get data for %q: %w", path, err)
			}
			view.Data[path] = data
		}
	}

	return view, nil
}

// VerifyView verifies an EvidenceView.
func VerifyView(view *EvidenceView) (bool, error) {
	for _, proof := range view.Proofs {
		// Verify each proof matches the view's root
		if proof.Root != view.RootHash {
			return false, fmt.Errorf("proof root mismatch for path %s", proof.LeafPath)
		}

		valid, err := VerifyProof(&proof)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, fmt.Errorf("invalid proof for path %s", proof.LeafPath)
		}
	}

	return true, nil
}

// canonicalJSON produces deterministic JSON with sorted keys.
func canonicalJSON(v any) ([]byte, error) {
	// Marshal to get standard JSON
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// For objects, we need to ensure keys are sorted
	// Unmarshal and re-marshal with sorted keys
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return marshalCanonical(raw)
}

// marshalCanonical produces canonical JSON (sorted keys).
func marshalCanonical(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		return marshalCanonicalObject(val)
	case []any:
		return marshalCanonicalArray(val)
	default:
		return json.Marshal(v)
	}
}

func marshalCanonicalObject(m map[string]any) ([]byte, error) {
	// Get sorted keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical JSON
	var buf bytes.Buffer
	buf.WriteByte('{')

	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}

		keyJSON, _ := json.Marshal(k)
		buf.Write(keyJSON)
		buf.WriteByte(':')

		valJSON, err := marshalCanonical(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(valJSON)
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshalCanonicalArray(arr []any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')

	for i, elem := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}

		elemJSON, err := marshalCanonical(elem)
		if err != nil {
			return nil, err
		}
		buf.Write(elemJSON)
	}

	buf.WriteByte(']')
	return buf.Bytes(), nil
}
