// merkle.go implements a deterministic Merkle tree over EvidencePack manifest
// entries, enabling privacy-preserving single-entry inclusion proofs (MIN-512).
//
// A verifier can confirm that one manifest entry (e.g. a single receipt) belongs
// to a pack identified by its entries_merkle_root WITHOUT possessing the other
// entries. Combined with SD-JWT selective disclosure (core/pkg/crypto/sdjwt),
// this lets an auditor confirm "this DENY happened under policy_hash X at time T"
// while the rest of the pack's payloads stay sealed.
//
// Construction (normative, see protocols/spec/evidence-pack-v1.md §14):
//   - Entries are sorted lexicographically by path (identical ordering to the
//     manifest hash of §5.1), so the tree binds to the same canonical entry set.
//   - Leaf  = SHA-256(0x00 || JCS(canonicalEntry))   (domain-separated)
//   - Inner = SHA-256(0x01 || left || right)          (domain-separated)
//   - Odd levels duplicate the final node. Leaf/inner domain tags prevent
//     second-preimage and type-confusion attacks.
//
// All hashes are raw 32-byte SHA-256 digests internally; the merkle root is
// surfaced as a `sha256:<hex>` string to match the rest of the pack format.
package evidencepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	merkleLeafPrefix  = 0x00
	merkleInnerPrefix = 0x01
)

// canonicalEntry is the exact, ordered field set hashed into a Merkle leaf.
// It mirrors ManifestEntry but is declared independently so that adding
// presentation-only fields to ManifestEntry can never silently change leaf
// hashes. JCS sorts keys, so field order here is documentation only.
type canonicalEntry struct {
	Path        string `json:"path"`
	ContentHash string `json:"content_hash"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
}

// LeafHash returns the domain-separated Merkle leaf hash for a manifest entry
// as a `sha256:<hex>` string. The leaf binds path + content_hash + size +
// content_type, so a verifier holding only this entry can recompute it exactly.
func LeafHash(entry ManifestEntry) (string, error) {
	raw, err := leafDigest(entry)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(raw), nil
}

func leafDigest(entry ManifestEntry) ([]byte, error) {
	data, err := canonicalize.JCS(canonicalEntry{
		Path:        entry.Path,
		ContentHash: entry.ContentHash,
		Size:        entry.Size,
		ContentType: entry.ContentType,
	})
	if err != nil {
		return nil, fmt.Errorf("canonicalize entry %q: %w", entry.Path, err)
	}
	h := sha256.New()
	h.Write([]byte{merkleLeafPrefix})
	h.Write(data)
	return h.Sum(nil), nil
}

func innerDigest(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{merkleInnerPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// sortedLeafDigests returns leaf digests for the manifest entries in canonical
// (path-sorted) order, plus the sorted entries for index lookups.
func sortedLeafDigests(entries []ManifestEntry) ([][]byte, []ManifestEntry, error) {
	sorted := make([]ManifestEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	leaves := make([][]byte, len(sorted))
	for i, e := range sorted {
		d, err := leafDigest(e)
		if err != nil {
			return nil, nil, err
		}
		leaves[i] = d
	}
	return leaves, sorted, nil
}

// ComputeEntriesMerkleRoot computes the deterministic Merkle root over a
// manifest's entries as a `sha256:<hex>` string. An empty entry set is an error
// (an EvidencePack always has at least one entry).
func ComputeEntriesMerkleRoot(entries []ManifestEntry) (string, error) {
	leaves, _, err := sortedLeafDigests(entries)
	if err != nil {
		return "", err
	}
	root, err := reduceToRoot(leaves)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(root), nil
}

func reduceToRoot(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("merkle: no entries to hash")
	}
	level := leaves
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // odd node duplicates itself
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, innerDigest(left, right))
		}
		level = next
	}
	return level[0], nil
}

// MerkleProofStep is one sibling on the audit path from a leaf to the root.
type MerkleProofStep struct {
	// SiblingHash is the `sha256:<hex>` digest of the sibling node at this level.
	SiblingHash string `json:"sibling_hash"`
	// Right reports whether the sibling sits to the RIGHT of the running hash.
	// When false, the sibling is on the left (running hash is the right child).
	Right bool `json:"right"`
}

// BuildInclusionPath builds the Merkle audit path for the entry at the given
// path. It returns the ordered proof steps and the computed root. The entry
// MUST exist in entries (matched by Path) or an error is returned.
func BuildInclusionPath(entries []ManifestEntry, entryPath string) ([]MerkleProofStep, string, error) {
	leaves, sorted, err := sortedLeafDigests(entries)
	if err != nil {
		return nil, "", err
	}

	idx := -1
	for i, e := range sorted {
		if e.Path == entryPath {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, "", fmt.Errorf("merkle: entry %q not found in manifest", entryPath)
	}

	var steps []MerkleProofStep
	level := leaves
	pos := idx
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			if i == pos { // running node is the left child; sibling on the right
				steps = append(steps, MerkleProofStep{
					SiblingHash: "sha256:" + hex.EncodeToString(right),
					Right:       true,
				})
			} else if i+1 == pos { // running node is the right child; sibling on the left
				steps = append(steps, MerkleProofStep{
					SiblingHash: "sha256:" + hex.EncodeToString(left),
					Right:       false,
				})
			}
			next = append(next, innerDigest(left, right))
		}
		pos /= 2
		level = next
	}

	root := "sha256:" + hex.EncodeToString(level[0])
	return steps, root, nil
}

// VerifyInclusionPath recomputes the Merkle root from a leaf hash and an audit
// path, returning the derived root as `sha256:<hex>`. It performs no comparison
// itself; callers compare the result against a trusted root.
func VerifyInclusionPath(leafHash string, steps []MerkleProofStep) (string, error) {
	running, err := decodeSHA256(leafHash)
	if err != nil {
		return "", fmt.Errorf("merkle: invalid leaf hash: %w", err)
	}
	for i, step := range steps {
		sib, err := decodeSHA256(step.SiblingHash)
		if err != nil {
			return "", fmt.Errorf("merkle: invalid sibling hash at step %d: %w", i, err)
		}
		if step.Right {
			running = innerDigest(running, sib)
		} else {
			running = innerDigest(sib, running)
		}
	}
	return "sha256:" + hex.EncodeToString(running), nil
}

// decodeSHA256 parses a `sha256:<64 hex>` string into 32 raw bytes.
func decodeSHA256(s string) ([]byte, error) {
	const prefix = "sha256:"
	if !bytes.HasPrefix([]byte(s), []byte(prefix)) {
		return nil, fmt.Errorf("missing sha256: prefix")
	}
	raw, err := hex.DecodeString(s[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("expected %d bytes, got %d", sha256.Size, len(raw))
	}
	return raw, nil
}
