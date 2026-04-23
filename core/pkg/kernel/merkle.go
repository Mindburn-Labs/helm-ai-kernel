// Package kernel provides EvidencePack Merkleization per Addendum 12.X.
package kernel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Merkle tree prefixes per Addendum 12.X.1
const (
	LeafPrefix = "helm:evidence:leaf:v1"
	NodePrefix = "helm:evidence:node:v1"
)

// MerkleLeaf represents a leaf in the Merkle tree.
type MerkleLeaf struct {
	Path      string `json:"path"`      // JSON Pointer path
	LeafBytes []byte `json:"-"`         // Computed leaf bytes
	LeafHash  string `json:"leaf_hash"` // SHA256 of leaf bytes
}

// MerkleTree represents a Merkle tree for an EvidencePack.
type MerkleTree struct {
	Leaves []MerkleLeaf `json:"leaves"`
	Root   string       `json:"root"`
	Levels [][]string   `json:"-"` // Internal node hashes by level
}

// InclusionProof demonstrates that a leaf is part of the Merkle tree.
type InclusionProof struct {
	ProofID    string      `json:"proof_id"`
	LeafPath   string      `json:"leaf_path"`
	LeafHash   string      `json:"leaf_hash"`
	MerkleRoot string      `json:"merkle_root"`
	ProofPath  []ProofStep `json:"proof_path"`
}

// ProofStep represents one step in an inclusion proof.
type ProofStep struct {
	Side        string `json:"side"` // "L" or "R"
	SiblingHash string `json:"sibling_hash"`
}

// SealedField represents a sealed (undisclosed) field.
type SealedField struct {
	Path       string `json:"path"`
	Commitment string `json:"commitment"` // Hash of the value
	Reason     string `json:"reason,omitempty"`
}

// EvidenceView is a derived view with selective disclosure.
type EvidenceView struct {
	ViewID           string           `json:"view_id"`
	EvidencePackHash string           `json:"evidence_pack_hash"`
	ViewPolicyID     string           `json:"view_policy_id"`
	Disclosed        map[string]any   `json:"disclosed"`
	Sealed           []SealedField    `json:"sealed"`
	Proofs           []InclusionProof `json:"proofs"`
	ViewHash         string           `json:"view_hash"`
	CreatedAt        string           `json:"created_at"`
}

// MerkleTreeBuilder builds Merkle trees for EvidencePacks.
type MerkleTreeBuilder struct {
	transformer *CSNFTransformer
}

// NewMerkleTreeBuilder creates a new Merkle tree builder.
func NewMerkleTreeBuilder() *MerkleTreeBuilder {
	return &MerkleTreeBuilder{
		transformer: NewCSNFTransformer(),
	}
}

// BuildTree constructs a Merkle tree from an object.
// Per Addendum 12.X.1: Leaves are sorted by JSON Pointer path.
func (b *MerkleTreeBuilder) BuildTree(obj map[string]any) (*MerkleTree, error) {
	// 1. Extract all paths and values
	pathValues := b.extractPathValues(obj, "")

	// 2. Sort paths lexicographically (per Addendum 12.X.1)
	paths := make([]string, 0, len(pathValues))
	for path := range pathValues {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// 3. Build leaves
	leaves := make([]MerkleLeaf, len(paths))
	for i, path := range paths {
		value := pathValues[path]

		// Canonicalize value
		canonical, err := b.getCanonicalBytes(value)
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize value at %s: %w", path, err)
		}

		// Build leaf bytes
		leafBytes := b.buildLeafBytes(path, canonical)
		leafHash := sha256Hex(leafBytes)

		leaves[i] = MerkleLeaf{
			Path:      path,
			LeafBytes: leafBytes,
			LeafHash:  leafHash,
		}
	}

	// 4. Build tree bottom-up
	tree := &MerkleTree{Leaves: leaves}

	if len(leaves) == 0 {
		// Empty tree
		tree.Root = sha256Hex([]byte{})
		return tree, nil
	}

	// Extract leaf hashes as first level
	currentLevel := make([]string, len(leaves))
	for i, leaf := range leaves {
		currentLevel[i] = leaf.LeafHash
	}
	tree.Levels = append(tree.Levels, currentLevel)

	// Build up levels until we have a root
	for len(currentLevel) > 1 {
		currentLevel = b.buildNextLevel(currentLevel)
		tree.Levels = append(tree.Levels, currentLevel)
	}

	tree.Root = currentLevel[0]
	return tree, nil
}

// extractPathValues recursively extracts path -> value mappings.
//
//nolint:gocognit // complexity acceptable
func (b *MerkleTreeBuilder) extractPathValues(obj any, prefix string) map[string]any {
	result := make(map[string]any)

	switch v := obj.(type) {
	case map[string]any:
		for key, val := range v {
			childPath := prefix + "/" + key
			// Recursively extract nested objects
			if nested, ok := val.(map[string]any); ok {
				for k, vv := range b.extractPathValues(nested, childPath) {
					result[k] = vv
				}
			} else if arr, ok := val.([]any); ok {
				// Handle arrays
				for i, elem := range arr {
					elemPath := fmt.Sprintf("%s/%d", childPath, i)
					if nested, ok := elem.(map[string]any); ok {
						for k, vv := range b.extractPathValues(nested, elemPath) {
							result[k] = vv
						}
					} else {
						result[elemPath] = elem
					}
				}
			} else {
				result[childPath] = val
			}
		}
	default:
		if prefix != "" {
			result[prefix] = obj
		}
	}

	return result
}

// buildLeafBytes constructs leaf bytes per Addendum 12.X.1.
// Format: "helm:evidence:leaf:v1\0" || path_utf8 || "\0" || CanonicalBytes
func (b *MerkleTreeBuilder) buildLeafBytes(path string, canonicalValue []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(LeafPrefix)
	buf.WriteByte(0) // Null terminator
	buf.WriteString(path)
	buf.WriteByte(0) // Null separator
	buf.Write(canonicalValue)
	return buf.Bytes()
}

// buildNextLevel computes the next level up in the Merkle tree.
func (b *MerkleTreeBuilder) buildNextLevel(level []string) []string {
	// If odd number of nodes, duplicate the last one
	if len(level)%2 == 1 {
		level = append(level, level[len(level)-1])
	}

	nextLevel := make([]string, len(level)/2)
	for i := 0; i < len(level); i += 2 {
		nextLevel[i/2] = buildNodeHash(level[i], level[i+1])
	}
	return nextLevel
}

// buildNodeHash computes an internal node hash.
// Per Addendum 12.X.1: "helm:evidence:node:v1\0" || left_hash || right_hash
func buildNodeHash(left, right string) string {
	var buf bytes.Buffer
	buf.WriteString(NodePrefix)
	buf.WriteByte(0)
	buf.Write(hexToBytes(left))
	buf.Write(hexToBytes(right))
	return sha256Hex(buf.Bytes())
}

// getCanonicalBytes gets CSNF+JCS bytes for a value.
func (b *MerkleTreeBuilder) getCanonicalBytes(value any) ([]byte, error) {
	// Apply CSNF transformation
	transformed, err := b.transformer.Transform(value)
	if err != nil {
		return nil, err
	}

	// Serialize to JSON (JCS would sort keys)
	// Note: Go's json.Marshal doesn't guarantee key order, but for simple values this is fine
	// A full implementation would use a JCS library
	return json.Marshal(transformed)
}

// GenerateProof generates an inclusion proof for a path.
func (tree *MerkleTree) GenerateProof(path string) (*InclusionProof, error) {
	// Find the leaf index
	leafIdx := -1
	for i, leaf := range tree.Leaves {
		if leaf.Path == path {
			leafIdx = i
			break
		}
	}
	if leafIdx < 0 {
		return nil, fmt.Errorf("path not found in tree: %s", path)
	}

	leaf := tree.Leaves[leafIdx]
	proof := &InclusionProof{
		ProofID:    generateProofID(path, tree.Root),
		LeafPath:   path,
		LeafHash:   leaf.LeafHash,
		MerkleRoot: tree.Root,
		ProofPath:  []ProofStep{},
	}

	// Walk up the tree collecting siblings
	currentIdx := leafIdx
	for level := 0; level < len(tree.Levels)-1; level++ {
		levelNodes := tree.Levels[level]

		// Determine sibling
		var siblingIdx int
		var side string
		if currentIdx%2 == 0 {
			// Current is left child, sibling is right
			siblingIdx = currentIdx + 1
			if siblingIdx >= len(levelNodes) {
				siblingIdx = currentIdx // Duplicated node case
			}
			side = "R"
		} else {
			// Current is right child, sibling is left
			siblingIdx = currentIdx - 1
			side = "L"
		}

		proof.ProofPath = append(proof.ProofPath, ProofStep{
			Side:        side,
			SiblingHash: levelNodes[siblingIdx],
		})

		currentIdx /= 2
	}

	return proof, nil
}

// VerifyProof verifies an inclusion proof against the expected root.
func VerifyProof(proof InclusionProof, expectedRoot string) bool {
	currentHash := proof.LeafHash

	for _, step := range proof.ProofPath {
		if step.Side == "L" {
			// Sibling is on the left
			currentHash = buildNodeHash(step.SiblingHash, currentHash)
		} else {
			// Sibling is on the right
			currentHash = buildNodeHash(currentHash, step.SiblingHash)
		}
	}

	return currentHash == expectedRoot
}

// ViewPolicy defines disclosure rules for EvidenceView derivation.
type ViewPolicy struct {
	PolicyID        string           `json:"policy_id"`
	Name            string           `json:"name"`
	DisclosureRules []DisclosureRule `json:"disclosure_rules"`
}

// DisclosureRule defines how to handle a path pattern.
type DisclosureRule struct {
	PathPattern string `json:"path_pattern"` // Glob-style pattern
	Action      string `json:"action"`       // "DISCLOSE", "SEAL", "REDACT"
	Reason      string `json:"reason,omitempty"`
}

// DeriveEvidenceView creates an EvidenceView from an EvidencePack.
// Per Addendum 12.X.4: Same inputs MUST yield identical outputs.
func DeriveEvidenceView(pack map[string]any, tree *MerkleTree, policy ViewPolicy, timestamp string) (*EvidenceView, error) {
	view := &EvidenceView{
		ViewID:           deriveViewID(tree.Root, policy.PolicyID),
		EvidencePackHash: tree.Root,
		ViewPolicyID:     policy.PolicyID,
		Disclosed:        make(map[string]any),
		Sealed:           []SealedField{},
		Proofs:           []InclusionProof{},
		CreatedAt:        timestamp,
	}

	// Process each leaf according to policy
	for _, leaf := range tree.Leaves {
		action, reason := matchPolicy(leaf.Path, policy)

		switch action {
		case "DISCLOSE":
			// Get the value from pack
			value := getValueAtPath(pack, leaf.Path)
			view.Disclosed[leaf.Path] = value

			// Generate inclusion proof
			proof, err := tree.GenerateProof(leaf.Path)
			if err != nil {
				return nil, err
			}
			view.Proofs = append(view.Proofs, *proof)

		case "SEAL":
			view.Sealed = append(view.Sealed, SealedField{
				Path:       leaf.Path,
				Commitment: leaf.LeafHash,
				Reason:     reason,
			})

		case "REDACT":
			// Don't include in view at all
		}
	}

	// Sort sealed fields for determinism
	sort.Slice(view.Sealed, func(i, j int) bool {
		return view.Sealed[i].Path < view.Sealed[j].Path
	})

	// Sort proofs for determinism
	sort.Slice(view.Proofs, func(i, j int) bool {
		return view.Proofs[i].LeafPath < view.Proofs[j].LeafPath
	})

	// Compute view hash
	viewBytes, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	view.ViewHash = sha256Hex(viewBytes)

	return view, nil
}

// Helper functions

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func hexToBytes(s string) []byte {
	// Remove "sha256:" prefix if present
	s = strings.TrimPrefix(s, "sha256:")
	bytes, _ := hex.DecodeString(s)
	return bytes
}

func generateProofID(path, root string) string {
	input := path + ":" + root
	hash := sha256.Sum256([]byte(input))
	return "proof_" + hex.EncodeToString(hash[:8])
}

func deriveViewID(packHash, policyID string) string {
	input := packHash + ":" + policyID
	hash := sha256.Sum256([]byte(input))
	return "view_" + hex.EncodeToString(hash[:8])
}

func matchPolicy(path string, policy ViewPolicy) (action, reason string) {
	for _, rule := range policy.DisclosureRules {
		if matchPath(path, rule.PathPattern) {
			return rule.Action, rule.Reason
		}
	}
	// Default: seal unknown paths
	return "SEAL", "no matching policy rule"
}

func matchPath(path, pattern string) bool {
	// Simple glob matching
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/")
	}
	return path == pattern
}

func getValueAtPath(obj map[string]any, path string) any {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := any(obj)

	for _, part := range parts {
		if part == "" {
			continue
		}

		switch v := current.(type) {
		case map[string]any:
			current = v[part]
		default:
			return nil
		}
	}

	return current
}
