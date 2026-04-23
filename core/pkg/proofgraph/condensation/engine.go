// Package condensation implements the HELM Proof Condensation engine.
// It provides cryptographic compaction of receipt chains using incremental
// Merkle trees, enabling space-efficient long-term archival while
// preserving full audit verifiability through inclusion proofs.
package condensation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ── Errors ───────────────────────────────────────────────────────────

var (
	ErrEmptyReceipts    = errors.New("condensation: no receipts to condense")
	ErrInvalidProof     = errors.New("condensation: invalid inclusion proof")
	ErrCheckpointExists = errors.New("condensation: checkpoint already exists for this window")
	ErrReceiptNotFound  = errors.New("condensation: receipt not found in checkpoint")
)

// ── Types ────────────────────────────────────────────────────────────

// RiskTier classifies the evidence retention requirement.
type RiskTier int

const (
	RiskLow    RiskTier = 0 // T0–T1: condensable after checkpoint
	RiskMedium RiskTier = 1 // T2: full receipts + periodic checkpoints
	RiskHigh   RiskTier = 2 // T3+: full retention, no condensation
)

// Receipt is a minimal receipt representation for condensation.
type Receipt struct {
	ID       string   `json:"id"`
	Hash     string   `json:"hash"` // SHA-256 of canonical receipt content
	RiskTier RiskTier `json:"risk_tier"`
}

// Checkpoint represents a condensation checkpoint over a window of receipts.
type Checkpoint struct {
	ID          string    `json:"id"`
	MerkleRoot  string    `json:"merkle_root"`
	ReceiptIDs  []string  `json:"receipt_ids"` // IDs included in this checkpoint
	LeafCount   int       `json:"leaf_count"`
	CreatedAt   time.Time `json:"created_at"`
	WindowStart int64     `json:"window_start"` // First Lamport clock in window
	WindowEnd   int64     `json:"window_end"`   // Last Lamport clock in window
}

// InclusionProof proves a receipt was included in a checkpoint.
type InclusionProof struct {
	ReceiptID    string   `json:"receipt_id"`
	ReceiptHash  string   `json:"receipt_hash"`
	MerkleRoot   string   `json:"merkle_root"`
	Siblings     []string `json:"siblings"`   // Sibling hashes for path to root
	LeafIndex    int      `json:"leaf_index"` // Position in the leaf set
	LeafCount    int      `json:"leaf_count"`
	CheckpointID string   `json:"checkpoint_id"`
}

// CondensedReceipt replaces a full receipt after condensation.
// It contains only the inclusion proof — sufficient for audit verification.
type CondensedReceipt struct {
	OriginalID string          `json:"original_id"`
	Proof      *InclusionProof `json:"proof"`
}

// ── Engine ───────────────────────────────────────────────────────────

// Engine manages the condensation lifecycle: accumulating receipts,
// creating checkpoints, generating inclusion proofs, and verifying them.
type Engine struct {
	mu          sync.RWMutex
	accumulated []Receipt
	checkpoints map[string]*Checkpoint
	proofs      map[string]*InclusionProof // receiptID → proof
	clock       func() time.Time
}

// NewEngine creates a new condensation engine.
func NewEngine() *Engine {
	return &Engine{
		checkpoints: make(map[string]*Checkpoint),
		proofs:      make(map[string]*InclusionProof),
		clock:       time.Now,
	}
}

// WithClock overrides the engine clock for deterministic testing.
func (e *Engine) WithClock(clock func() time.Time) *Engine {
	e.clock = clock
	return e
}

// Accumulate adds a receipt to the pending set for the next checkpoint.
func (e *Engine) Accumulate(r Receipt) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accumulated = append(e.accumulated, r)
}

// AccumulatedCount returns the number of receipts pending checkpoint.
func (e *Engine) AccumulatedCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.accumulated)
}

// Checkpoint creates a Merkle checkpoint over all accumulated receipts,
// generates inclusion proofs for each, and resets the accumulator.
func (e *Engine) CreateCheckpoint(windowStart, windowEnd int64) (*Checkpoint, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.accumulated) == 0 {
		return nil, ErrEmptyReceipts
	}

	// Build leaf hashes
	leaves := make([]string, len(e.accumulated))
	receiptIDs := make([]string, len(e.accumulated))
	for i, r := range e.accumulated {
		leaves[i] = r.Hash
		receiptIDs[i] = r.ID
	}

	// Compute Merkle root
	root := computeMerkleRoot(leaves)

	// Create checkpoint
	cpID := fmt.Sprintf("cp-%s", hashString(root + fmt.Sprintf("%d-%d", windowStart, windowEnd))[:12])
	if _, exists := e.checkpoints[cpID]; exists {
		return nil, ErrCheckpointExists
	}
	cp := &Checkpoint{
		ID:          cpID,
		MerkleRoot:  root,
		ReceiptIDs:  receiptIDs,
		LeafCount:   len(leaves),
		CreatedAt:   e.clock(),
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
	}
	e.checkpoints[cpID] = cp

	// Generate inclusion proofs for all receipts
	for i, r := range e.accumulated {
		proof := generateInclusionProof(leaves, i, cpID, r.ID, r.Hash, root)
		e.proofs[r.ID] = proof
	}

	// Reset accumulator
	e.accumulated = nil

	return cp, nil
}

// GetProof returns the inclusion proof for a receipt.
func (e *Engine) GetProof(receiptID string) (*InclusionProof, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	proof, ok := e.proofs[receiptID]
	if !ok {
		return nil, ErrReceiptNotFound
	}
	return proof, nil
}

// Condense creates a CondensedReceipt for a low-risk receipt that has
// been checkpointed. Returns the condensed form suitable for replacing
// the full receipt in storage.
func (e *Engine) Condense(receiptID string) (*CondensedReceipt, error) {
	proof, err := e.GetProof(receiptID)
	if err != nil {
		return nil, err
	}
	return &CondensedReceipt{
		OriginalID: receiptID,
		Proof:      proof,
	}, nil
}

// ── Verification ─────────────────────────────────────────────────────

// VerifyInclusion verifies that an inclusion proof is valid against
// the given Merkle root.
func VerifyInclusion(proof *InclusionProof) (bool, error) {
	if proof == nil {
		return false, ErrInvalidProof
	}
	if proof.LeafCount == 0 {
		return false, ErrInvalidProof
	}

	// Recompute root from leaf hash and sibling path
	current := proof.ReceiptHash
	idx := proof.LeafIndex

	for _, sibling := range proof.Siblings {
		if idx%2 == 0 {
			current = hashPair(current, sibling)
		} else {
			current = hashPair(sibling, current)
		}
		idx /= 2
	}

	return current == proof.MerkleRoot, nil
}

// VerifyCheckpoint verifies that a checkpoint's Merkle root matches
// when recomputed from the given receipt hashes.
func VerifyCheckpoint(cp *Checkpoint, receiptHashes []string) (bool, error) {
	if cp == nil || len(receiptHashes) == 0 {
		return false, ErrEmptyReceipts
	}
	if len(receiptHashes) != cp.LeafCount {
		return false, fmt.Errorf("condensation: expected %d receipts, got %d", cp.LeafCount, len(receiptHashes))
	}

	root := computeMerkleRoot(receiptHashes)
	return root == cp.MerkleRoot, nil
}

// ── Merkle Tree Implementation ───────────────────────────────────────

// computeMerkleRoot computes the Merkle root of a set of leaf hashes.
// Uses SHA-256 pair hashing. Odd leaves are promoted (duplicated).
func computeMerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return hashString("")
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Pad to even length by duplicating last leaf
	level := make([]string, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		var next []string
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				next = append(next, hashPair(level[i], level[i]))
			}
		}
		level = next
	}

	return level[0]
}

// generateInclusionProof generates a Merkle inclusion proof for the
// leaf at the given index.
func generateInclusionProof(leaves []string, leafIndex int, cpID, receiptID, receiptHash, merkleRoot string) *InclusionProof {
	if len(leaves) == 0 {
		return nil
	}

	var siblings []string
	level := make([]string, len(leaves))
	copy(level, leaves)
	idx := leafIndex

	for len(level) > 1 {
		var next []string
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}

			// Record sibling for the path element
			if i == idx-(idx%2) {
				if idx%2 == 0 {
					siblings = append(siblings, right)
				} else {
					siblings = append(siblings, left)
				}
			}

			next = append(next, hashPair(left, right))
		}
		level = next
		idx /= 2
	}

	return &InclusionProof{
		ReceiptID:    receiptID,
		ReceiptHash:  receiptHash,
		MerkleRoot:   merkleRoot,
		Siblings:     siblings,
		LeafIndex:    leafIndex,
		LeafCount:    len(leaves),
		CheckpointID: cpID,
	}
}

func hashPair(a, b string) string {
	h := sha256.New()
	h.Write([]byte(a))
	h.Write([]byte(b))
	return hex.EncodeToString(h.Sum(nil))
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// MarshalJSON serializes a checkpoint to JSON.
func (cp *Checkpoint) MarshalJSON() ([]byte, error) {
	type Alias Checkpoint
	return json.Marshal((*Alias)(cp))
}
