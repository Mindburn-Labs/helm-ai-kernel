package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel/csnf"
)

type MerkleLeaf struct {
	Path      string
	LeafBytes []byte
	LeafHash  string
}

type MerkleTree struct {
	Leaves []MerkleLeaf
	Root   string
	Nodes  [][]string // levels of node hashes
}

// BuildMerkleTree constructs a Merkle Tree from a map of path->value.
func BuildMerkleTree(data map[string]interface{}) (*MerkleTree, error) {
	// 1. Extract and sort paths
	paths := make([]string, 0, len(data))
	for k := range data {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	// 2. Build leaves
	leaves := make([]MerkleLeaf, len(paths))
	for i, path := range paths {
		value := data[path]

		// Canonicalize and Hash (CSNF)
		// Spec says: CanonicalBytes(CSA_subobject)
		// csnf.Hash returns string hash. csnf.Canonicalize returns interface{}.
		// We need bytes of canonical form.
		// csnf package only exposes Canonicalize and Hash.
		// Let's assume we can get bytes via csnf.Hash implementation logic (marshal canonical).
		// But csnf.Hash does internal marshal.
		// We should probably add CanonicalBytes to csnf package or replicate logic.
		// For now, let's use csnf.Hash(val) and rely on that?
		// No, leaf calculation is: "helm:evidence:leaf:v1\0" || path || "\0" || CanonicalBytes(val)
		// Validation uses SHA256(leaf_bytes).
		// So we need the bytes.
		// I will implement a helper here to get canonical bytes using csnf.Canonicalize + json.Marshal.

		can, err := csnf.Canonicalize(value)
		if err != nil {
			return nil, err
		}

		// Use standard json marshal on canonical object (simulating JCS)
		// Since we stripped forbidden types, stdlib marshal is close to JCS (sorted keys).
		canBytes, err := json.Marshal(can)
		if err != nil {
			return nil, err
		}

		leafBytes := buildLeafBytes(path, canBytes)
		leaves[i] = MerkleLeaf{
			Path:      path,
			LeafBytes: leafBytes,
			LeafHash:  sha256Hex(leafBytes),
		}
	}

	// 3. Build tree bottom-up
	if len(leaves) == 0 {
		return &MerkleTree{Root: ""}, nil // Or specific empty root? Spec doesn't say.
	}

	tree := &MerkleTree{Leaves: leaves}
	currentLevel := extractHashes(leaves)

	for len(currentLevel) > 1 {
		tree.Nodes = append(tree.Nodes, currentLevel)
		currentLevel = buildNextLevel(currentLevel)
	}

	tree.Root = currentLevel[0]
	// Store root level too? Spec implies Nodes stores levels.
	tree.Nodes = append(tree.Nodes, currentLevel)

	return tree, nil
}

func buildLeafBytes(path string, canonical []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("helm:evidence:leaf:v1")
	buf.WriteByte(0)
	buf.WriteString(path)
	buf.WriteByte(0)
	buf.Write(canonical)
	return buf.Bytes()
}

func extractHashes(leaves []MerkleLeaf) []string {
	hashes := make([]string, len(leaves))
	for i, l := range leaves {
		hashes[i] = l.LeafHash
	}
	return hashes
}

func buildNextLevel(hashes []string) []string {
	count := len(hashes)
	if count%2 != 0 {
		hashes = append(hashes, hashes[count-1]) // Duplicate last
		count++
	}

	nextLevel := make([]string, count/2)
	for i := 0; i < count; i += 2 {
		nextLevel[i/2] = buildNodeHash(hashes[i], hashes[i+1])
	}
	return nextLevel
}

func buildNodeHash(left, right string) string {
	var buf bytes.Buffer
	buf.WriteString("helm:evidence:node:v1")
	buf.WriteByte(0)
	buf.Write(hexToBytes(left))
	buf.Write(hexToBytes(right))
	return sha256Hex(buf.Bytes())
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
