package translog

import (
	"encoding/hex"
	"fmt"
)

// InclusionProof is an RFC 6962 audit path proving that the leaf at
// LeafIndex is included in the tree of TreeSize with root RootHash.
// Hashes are lowercase hex SHA-256.
type InclusionProof struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	LeafHash  string   `json:"leaf_hash"`
	RootHash  string   `json:"root_hash"`
	AuditPath []string `json:"audit_path"`
}

// ConsistencyProof is an RFC 6962 consistency proof between the tree at
// OldSize (root OldRoot) and the tree at NewSize (root NewRoot).
type ConsistencyProof struct {
	OldSize         uint64   `json:"old_size"`
	NewSize         uint64   `json:"new_size"`
	OldRoot         string   `json:"old_root"`
	NewRoot         string   `json:"new_root"`
	ConsistencyPath []string `json:"consistency_path"`
}

// BuildInclusionProof computes PATH(leafIndex, D[treeSize]) over the
// given leaf hashes (RFC 6962 section 2.1.1). treeSize may be smaller
// than len(leafHashes) to prove inclusion under an older tree head.
func BuildInclusionProof(leafHashes [][HashSize]byte, leafIndex, treeSize uint64) (*InclusionProof, error) {
	if treeSize == 0 || treeSize > uint64(len(leafHashes)) {
		return nil, fmt.Errorf("translog: tree size %d out of range (have %d leaves)", treeSize, len(leafHashes))
	}
	if leafIndex >= treeSize {
		return nil, fmt.Errorf("translog: leaf index %d out of range for tree size %d", leafIndex, treeSize)
	}
	path := inclusionPath(leafHashes, leafIndex, 0, treeSize)
	root := subtreeRoot(leafHashes, 0, treeSize)
	return &InclusionProof{
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
		LeafHash:  hex.EncodeToString(leafHashes[leafIndex][:]),
		RootHash:  hex.EncodeToString(root[:]),
		AuditPath: encodePath(path),
	}, nil
}

// inclusionPath computes PATH(m, D[lo:hi]) for the leaf at absolute
// index m within the subtree [lo, hi).
func inclusionPath(leafHashes [][HashSize]byte, m, lo, hi uint64) [][HashSize]byte {
	n := hi - lo
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(n)
	if m < lo+k {
		path := inclusionPath(leafHashes, m, lo, lo+k)
		return append(path, subtreeRoot(leafHashes, lo+k, hi))
	}
	path := inclusionPath(leafHashes, m, lo+k, hi)
	return append(path, subtreeRoot(leafHashes, lo, lo+k))
}

// VerifyInclusion verifies an RFC 6962 inclusion proof against a trusted
// root hash (RFC 9162 section 2.1.3.2). It is a pure function: it never
// touches the log. Returns nil if the proof is valid.
func VerifyInclusion(proof *InclusionProof, trustedRoot string) error {
	if proof == nil {
		return fmt.Errorf("translog: nil inclusion proof")
	}
	if proof.TreeSize == 0 {
		return fmt.Errorf("translog: inclusion proof for empty tree")
	}
	if proof.LeafIndex >= proof.TreeSize {
		return fmt.Errorf("translog: leaf index %d out of range for tree size %d", proof.LeafIndex, proof.TreeSize)
	}
	leaf, err := decodeHash(proof.LeafHash)
	if err != nil {
		return fmt.Errorf("translog: bad leaf hash: %w", err)
	}
	root, err := decodeHash(trustedRoot)
	if err != nil {
		return fmt.Errorf("translog: bad root hash: %w", err)
	}
	path, err := decodePath(proof.AuditPath)
	if err != nil {
		return fmt.Errorf("translog: bad audit path: %w", err)
	}

	fn := proof.LeafIndex
	sn := proof.TreeSize - 1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return fmt.Errorf("translog: audit path longer than expected")
		}
		if fn%2 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("translog: audit path shorter than expected")
	}
	if r != root {
		return fmt.Errorf("translog: inclusion proof root mismatch: computed %x, trusted %s", r, trustedRoot)
	}
	return nil
}

// BuildConsistencyProof computes PROOF(oldSize, D[newSize]) over the
// given leaf hashes (RFC 6962 section 2.1.2).
func BuildConsistencyProof(leafHashes [][HashSize]byte, oldSize, newSize uint64) (*ConsistencyProof, error) {
	if newSize > uint64(len(leafHashes)) {
		return nil, fmt.Errorf("translog: new size %d out of range (have %d leaves)", newSize, len(leafHashes))
	}
	if oldSize == 0 || oldSize > newSize {
		return nil, fmt.Errorf("translog: old size %d out of range for new size %d", oldSize, newSize)
	}
	var path [][HashSize]byte
	if oldSize < newSize {
		path = consistencySubproof(leafHashes, oldSize, 0, newSize, true)
	}
	oldRoot := subtreeRoot(leafHashes, 0, oldSize)
	newRoot := subtreeRoot(leafHashes, 0, newSize)
	return &ConsistencyProof{
		OldSize:         oldSize,
		NewSize:         newSize,
		OldRoot:         hex.EncodeToString(oldRoot[:]),
		NewRoot:         hex.EncodeToString(newRoot[:]),
		ConsistencyPath: encodePath(path),
	}, nil
}

// consistencySubproof computes SUBPROOF(m, D[lo:hi], b) per RFC 6962
// section 2.1.2, where m is the absolute boundary index (old tree size).
func consistencySubproof(leafHashes [][HashSize]byte, m, lo, hi uint64, complete bool) [][HashSize]byte {
	if m == hi {
		if complete {
			return nil
		}
		return [][HashSize]byte{subtreeRoot(leafHashes, lo, hi)}
	}
	k := largestPowerOfTwoBelow(hi - lo)
	if m <= lo+k {
		path := consistencySubproof(leafHashes, m, lo, lo+k, complete)
		return append(path, subtreeRoot(leafHashes, lo+k, hi))
	}
	path := consistencySubproof(leafHashes, m, lo+k, hi, false)
	return append(path, subtreeRoot(leafHashes, lo, lo+k))
}

// VerifyConsistency verifies an RFC 6962 consistency proof between two
// tree heads (RFC 9162 section 2.1.4.2). It is a pure function. Returns
// nil if the new tree is a valid append-only extension of the old tree.
// In particular, two distinct roots claimed at the same tree size can
// never verify: that is equivocation (a split view).
func VerifyConsistency(proof *ConsistencyProof) error {
	if proof == nil {
		return fmt.Errorf("translog: nil consistency proof")
	}
	if proof.OldSize == 0 || proof.OldSize > proof.NewSize {
		return fmt.Errorf("translog: old size %d out of range for new size %d", proof.OldSize, proof.NewSize)
	}
	oldRoot, err := decodeHash(proof.OldRoot)
	if err != nil {
		return fmt.Errorf("translog: bad old root: %w", err)
	}
	newRoot, err := decodeHash(proof.NewRoot)
	if err != nil {
		return fmt.Errorf("translog: bad new root: %w", err)
	}
	path, err := decodePath(proof.ConsistencyPath)
	if err != nil {
		return fmt.Errorf("translog: bad consistency path: %w", err)
	}

	if proof.OldSize == proof.NewSize {
		if len(path) != 0 {
			return fmt.Errorf("translog: non-empty consistency path for equal tree sizes")
		}
		if oldRoot != newRoot {
			return fmt.Errorf("translog: equivocation: two distinct roots at tree size %d", proof.OldSize)
		}
		return nil
	}
	if len(path) == 0 {
		return fmt.Errorf("translog: empty consistency path for growing tree")
	}

	fn := proof.OldSize - 1
	sn := proof.NewSize - 1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}

	var fr, sr [HashSize]byte
	rest := path
	if fn != 0 {
		fr = rest[0]
		sr = rest[0]
		rest = rest[1:]
	} else {
		fr = oldRoot
		sr = oldRoot
	}

	for _, p := range rest {
		if sn == 0 {
			return fmt.Errorf("translog: consistency path longer than expected")
		}
		if fn%2 == 1 || fn == sn {
			fr = NodeHash(p, fr)
			sr = NodeHash(p, sr)
			if fn%2 == 0 {
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, p)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return fmt.Errorf("translog: consistency path shorter than expected")
	}
	if fr != oldRoot {
		return fmt.Errorf("translog: consistency proof does not reproduce old root (split view)")
	}
	if sr != newRoot {
		return fmt.Errorf("translog: consistency proof does not reproduce new root (split view)")
	}
	return nil
}

func encodePath(path [][HashSize]byte) []string {
	out := make([]string, len(path))
	for i, h := range path {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}

func decodePath(path []string) ([][HashSize]byte, error) {
	out := make([][HashSize]byte, len(path))
	for i, s := range path {
		h, err := decodeHash(s)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

func decodeHash(s string) ([HashSize]byte, error) {
	var out [HashSize]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != HashSize {
		return out, fmt.Errorf("expected %d-byte hash, got %d bytes", HashSize, len(b))
	}
	copy(out[:], b)
	return out, nil
}
