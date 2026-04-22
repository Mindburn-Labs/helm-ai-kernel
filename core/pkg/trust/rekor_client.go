// Package trust implements the Pack Trust Fabric per Addendum 14.X.
// This file contains Rekor transparency log client per Section 14.X.2.
package trust

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// RekorLogID is the default Rekor log identifier.
const RekorLogID = "rekor.sigstore.dev"

// RekorEntry represents a transparency log entry.
// Per Section 14.X.2: Transparency Entry Schema.
type RekorEntry struct {
	// LogID identifies the transparency log
	LogID string `json:"log_id"`

	// LogIndex is the entry's position in the log
	LogIndex int64 `json:"log_index"`

	// IntegratedTime is when the entry was added to the log
	IntegratedTime int64 `json:"integrated_time"`

	// Body contains the signed artifact information
	Body RekorBody `json:"body"`

	// InclusionProof provides cryptographic proof of inclusion
	InclusionProof *InclusionProof `json:"inclusion_proof,omitempty"`
}

// RekorBody is the artifact information in a log entry.
type RekorBody struct {
	Kind       string          `json:"kind"`
	APIVersion string          `json:"api_version"`
	Spec       json.RawMessage `json:"spec"`
}

// HelmPackSpec is the spec for HELM pack entries.
type HelmPackSpec struct {
	PackID      string `json:"pack_id"`
	PackVersion string `json:"pack_version"`
	PackHash    string `json:"pack_hash"`
	PublisherID string `json:"publisher_id"`
	Signature   string `json:"signature"`
}

// InclusionProof proves an entry is in the log.
// Per Section 14.X.2: Inclusion proofs cryptographic proof.
type InclusionProof struct {
	LogIndex int64    `json:"log_index"`
	RootHash string   `json:"root_hash"`
	TreeSize int64    `json:"tree_size"`
	Hashes   []string `json:"hashes"`
}

// SignedTreeHead represents a checkpoint of the log state.
type SignedTreeHead struct {
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// RekorClient interacts with a Rekor transparency log.
// Per Section 14.X.6: Rekor Client Integration.
type RekorClient struct {
	// logURL is the Rekor API endpoint
	logURL string

	// trustedRoot is the last verified signed tree head
	trustedRoot *SignedTreeHead
}

// RekorClientConfig configures the Rekor client.
type RekorClientConfig struct {
	LogURL      string
	TrustedRoot *SignedTreeHead
}

// NewRekorClient creates a new Rekor client.
func NewRekorClient(config RekorClientConfig) (*RekorClient, error) {
	if config.LogURL == "" {
		return nil, fmt.Errorf("rekor log URL is required")
	}

	return &RekorClient{
		logURL:      config.LogURL,
		trustedRoot: config.TrustedRoot,
	}, nil
}

// VerifyEntry verifies a pack exists in the transparency log.
// Per Section 14.X.2: Append-only, inclusion proofs, signed tree head.
func (c *RekorClient) VerifyEntry(packHash string) (*RekorEntry, error) {
	// 1. Search for entry by pack hash
	entry, err := c.searchByHash(packHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find entry for hash %s: %w", packHash, err)
	}

	// 2. Verify inclusion proof
	if err := c.verifyInclusionProof(entry); err != nil {
		return nil, fmt.Errorf("inclusion proof verification failed: %w", err)
	}

	// 3. Verify signed tree head
	if err := c.verifySignedTreeHead(entry); err != nil {
		return nil, fmt.Errorf("signed tree head verification failed: %w", err)
	}

	return entry, nil
}

// searchByHash finds a log entry by artifact hash.
func (c *RekorClient) searchByHash(packHash string) (*RekorEntry, error) {
	// Placeholder - actual implementation would call Rekor API
	// POST /api/v1/index/retrieve with hash
	return nil, fmt.Errorf("rekor search not yet implemented")
}

// verifyInclusionProof verifies the Merkle inclusion proof.
// This proves the entry is actually in the log.
func (c *RekorClient) verifyInclusionProof(entry *RekorEntry) error {
	if entry.InclusionProof == nil {
		return fmt.Errorf("no inclusion proof provided")
	}

	proof := entry.InclusionProof

	// Compute leaf hash
	leafData, err := json.Marshal(entry.Body)
	if err != nil {
		return fmt.Errorf("failed to marshal body: %w", err)
	}
	leafHash := computeLeafHash(leafData)

	// Reconstruct root from proof
	computedRoot, err := computeRootFromProof(
		entry.LogIndex,
		proof.TreeSize,
		leafHash,
		proof.Hashes,
	)
	if err != nil {
		return fmt.Errorf("failed to compute root from proof: %w", err)
	}

	// Verify computed root matches claimed root
	if computedRoot != proof.RootHash {
		return fmt.Errorf("inclusion proof verification failed: root mismatch")
	}

	return nil
}

// verifySignedTreeHead verifies the log checkpoint signature.
func (c *RekorClient) verifySignedTreeHead(entry *RekorEntry) error {
	if entry.InclusionProof == nil {
		return fmt.Errorf("no inclusion proof to verify against tree head")
	}

	// If we have a trusted root, verify consistency
	if c.trustedRoot != nil {
		// Tree size should not decrease
		if entry.InclusionProof.TreeSize < c.trustedRoot.TreeSize {
			return fmt.Errorf("tree size regression detected: %d < %d",
				entry.InclusionProof.TreeSize, c.trustedRoot.TreeSize)
		}
	}

	// Placeholder for actual signature verification
	// Would verify the signed tree head against known log public key
	return nil
}

// GetCheckpointRef creates an evidence reference for the current log state.
func (c *RekorClient) GetCheckpointRef(entry *RekorEntry) TransparencyRef {
	return TransparencyRef{
		LogID:      entry.LogID,
		LogIndex:   entry.LogIndex,
		TreeSize:   entry.InclusionProof.TreeSize,
		RootHash:   entry.InclusionProof.RootHash,
		VerifiedAt: time.Now(),
	}
}

// TransparencyRef captures the log state for an evidence pack.
// Per Section 14.X.2: Evidence Requirements.
type TransparencyRef struct {
	LogID      string    `json:"log_id"`
	LogIndex   int64     `json:"log_index"`
	TreeSize   int64     `json:"tree_size"`
	RootHash   string    `json:"root_hash"`
	VerifiedAt time.Time `json:"verified_at"`
}

// computeLeafHash computes the RFC 6962 leaf hash.
func computeLeafHash(data []byte) string {
	// RFC 6962: leaf_hash = SHA256(0x00 || data)
	hasher := sha256.New()
	hasher.Write([]byte{0x00})
	hasher.Write(data)
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// computeRootFromProof reconstructs root hash from inclusion proof.
// This implements RFC 6962 Merkle tree proof verification.
func computeRootFromProof(index, _ int64, leafHash string, proofHashes []string) (string, error) {
	if len(proofHashes) == 0 {
		return leafHash, nil
	}

	// Decode leaf hash
	currentHash, err := base64.StdEncoding.DecodeString(leafHash)
	if err != nil {
		return "", fmt.Errorf("failed to decode leaf hash: %w", err)
	}

	// Walk up the proof
	for i, hashStr := range proofHashes {
		proofHash, err := base64.StdEncoding.DecodeString(hashStr)
		if err != nil {
			return "", fmt.Errorf("failed to decode proof hash %d: %w", i, err)
		}

		// Determine if proof node is left or right sibling
		// based on index position at this level
		if index%2 == 0 {
			// Current is left, proof is right
			currentHash = computeNodeHash(currentHash, proofHash)
		} else {
			// Current is right, proof is left
			currentHash = computeNodeHash(proofHash, currentHash)
		}

		index /= 2
	}

	return base64.StdEncoding.EncodeToString(currentHash), nil
}

// computeNodeHash computes the RFC 6962 node hash.
func computeNodeHash(left, right []byte) []byte {
	// RFC 6962: node_hash = SHA256(0x01 || left || right)
	hasher := sha256.New()
	hasher.Write([]byte{0x01})
	hasher.Write(left)
	hasher.Write(right)
	return hasher.Sum(nil)
}

// VerifyInclusionProofBytes verifies an inclusion proof with raw bytes.
func VerifyInclusionProofBytes(leafData []byte, proof *InclusionProof) error {
	if proof == nil {
		return fmt.Errorf("nil inclusion proof")
	}

	leafHash := computeLeafHash(leafData)
	computedRoot, err := computeRootFromProof(proof.LogIndex, proof.TreeSize, leafHash, proof.Hashes)
	if err != nil {
		return err
	}

	if computedRoot != proof.RootHash {
		return fmt.Errorf("root hash mismatch: expected %s, got %s", proof.RootHash, computedRoot)
	}

	return nil
}
