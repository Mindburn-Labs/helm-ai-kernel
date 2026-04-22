// Package anchor provides transparency log anchoring for HELM's ProofGraph.
//
// Anchoring periodically submits Merkle roots from the ProofGraph to external
// transparency logs (Sigstore Rekor, RFC 3161 TSA), creating externally verifiable
// trust anchors that prove the integrity of the proof chain without trusting HELM.
//
// This implements the P4 ProofGraph anchoring strategy from HELM UCS v1.2.
package anchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AnchorBackend defines the interface for transparency log backends.
// Implementations include Sigstore Rekor v2 and RFC 3161 timestamping authorities.
type AnchorBackend interface {
	// Name returns the human-readable name of this backend (e.g., "rekor-v2", "rfc3161").
	Name() string

	// Anchor submits a Merkle root to the transparency log and returns an AnchorReceipt.
	// The receipt contains all information necessary to independently verify the anchoring.
	Anchor(ctx context.Context, req AnchorRequest) (*AnchorReceipt, error)

	// Verify checks that an AnchorReceipt is valid against the transparency log.
	Verify(ctx context.Context, receipt *AnchorReceipt) error
}

// AnchorRequest contains the data to be anchored.
type AnchorRequest struct {
	// MerkleRoot is the hex-encoded SHA-256 root of the ProofGraph subtree being anchored.
	MerkleRoot string `json:"merkle_root"`

	// FromLamport is the start of the Lamport clock range covered by this anchor.
	FromLamport uint64 `json:"from_lamport"`

	// ToLamport is the end of the Lamport clock range covered by this anchor.
	ToLamport uint64 `json:"to_lamport"`

	// NodeCount is the number of ProofGraph nodes covered by this anchor.
	NodeCount int `json:"node_count"`

	// HeadNodeIDs are the current DAG head node hashes at anchor time.
	HeadNodeIDs []string `json:"head_node_ids"`

	// Timestamp is the time the anchor request was created.
	Timestamp time.Time `json:"timestamp"`
}

// ComputeDigest returns a deterministic SHA-256 digest of the anchor request
// for signing/submission. Uses sorted JSON keys for determinism.
func (r *AnchorRequest) ComputeDigest() ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("anchor: marshal request: %w", err)
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// AnchorReceipt is the proof returned by a transparency log after anchoring.
type AnchorReceipt struct {
	// Backend identifies which transparency log produced this receipt.
	Backend string `json:"backend"`

	// Request is the original anchor request.
	Request AnchorRequest `json:"request"`

	// LogID is the transparency log's unique identifier (e.g., Rekor log ID).
	LogID string `json:"log_id"`

	// LogIndex is the entry's position in the transparency log.
	LogIndex int64 `json:"log_index"`

	// IntegratedTime is the timestamp assigned by the transparency log.
	IntegratedTime time.Time `json:"integrated_time"`

	// Signature is the transparency log's signature over the entry.
	Signature string `json:"signature"`

	// InclusionProof contains the Merkle inclusion proof from the log's tree.
	InclusionProof *LogInclusionProof `json:"inclusion_proof,omitempty"`

	// RawResponse is the full response from the transparency log for archival.
	RawResponse json.RawMessage `json:"raw_response,omitempty"`

	// ReceiptHash is the SHA-256 hash of this receipt for indexing.
	ReceiptHash string `json:"receipt_hash"`
}

// LogInclusionProof proves that the anchored entry exists in the transparency log's Merkle tree.
type LogInclusionProof struct {
	TreeSize   int64    `json:"tree_size"`
	RootHash   string   `json:"root_hash"`
	LogIndex   int64    `json:"log_index"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint,omitempty"`
}

// ComputeReceiptHash computes a deterministic hash of the receipt for indexing.
func (r *AnchorReceipt) ComputeReceiptHash() string {
	data, err := json.Marshal(struct {
		Backend        string        `json:"backend"`
		LogID          string        `json:"log_id"`
		LogIndex       int64         `json:"log_index"`
		IntegratedTime time.Time     `json:"integrated_time"`
		MerkleRoot     string        `json:"merkle_root"`
		Request        AnchorRequest `json:"request"`
	}{
		Backend:        r.Backend,
		LogID:          r.LogID,
		LogIndex:       r.LogIndex,
		IntegratedTime: r.IntegratedTime,
		MerkleRoot:     r.Request.MerkleRoot,
		Request:        r.Request,
	})
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
