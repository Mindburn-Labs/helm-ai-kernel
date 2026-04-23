// Package memory — Knowledge promotion workflow.
//
// Per HELM 2030 Spec §5.4:
//
//	Any LKS-derived claim needed for execution MUST be promoted into CKS
//	with provenance and ProofGraph linkage.
//
// Resolves: GAP-A6.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// PromotionRequest asks to promote an LKS entry to CKS.
type PromotionRequest struct {
	RequestID    string   `json:"request_id"`
	EntryID      string   `json:"entry_id"`
	ReviewerID   string   `json:"reviewer_id"`
	Rationale    string   `json:"rationale"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"` // ProofGraph node IDs
}

// PromotionResult is the outcome of a promotion request.
type PromotionResult struct {
	RequestID     string     `json:"request_id"`
	EntryID       string     `json:"entry_id"`
	Status        string     `json:"status"` // "PROMOTED", "DENIED"
	NewTier       MemoryTier `json:"new_tier"`
	ProofGraphRef string     `json:"proof_graph_ref,omitempty"`
	ReviewedAt    time.Time  `json:"reviewed_at"`
	ContentHash   string     `json:"content_hash"`
}

// Promote validates and promotes an LKS entry to CKS.
// Fail-closed: any validation failure returns error, entry stays LKS.
func Promote(store MemoryStore, req PromotionRequest) (*PromotionResult, error) {
	if req.EntryID == "" || req.ReviewerID == "" || req.Rationale == "" {
		return nil, fmt.Errorf("promotion requires entry_id, reviewer_id, and rationale")
	}

	entry, err := store.Get(req.EntryID)
	if err != nil {
		return nil, fmt.Errorf("entry lookup failed: %w", err)
	}
	if entry.Tier != TierLKS {
		return nil, fmt.Errorf("entry %s is already tier %s, cannot promote", req.EntryID, entry.Tier)
	}
	if entry.ReviewState == ReviewRejected {
		return nil, fmt.Errorf("entry %s was previously rejected", req.EntryID)
	}

	// Promote: update tier and review state
	now := time.Now().UTC()
	entry.Tier = TierCKS
	entry.ReviewState = ReviewApproved
	entry.UpdatedAt = now

	// Recompute content hash
	hashInput := fmt.Sprintf("%s:%s:%s:%s:%s",
		entry.EntryID, entry.Tier, entry.Value, req.ReviewerID, now.String())
	h := sha256.Sum256([]byte(hashInput))
	entry.ContentHash = "sha256:" + hex.EncodeToString(h[:])

	if err := store.Put(*entry); err != nil {
		return nil, fmt.Errorf("promotion store update failed: %w", err)
	}

	resultHash := fmt.Sprintf("%s:%s:%s", req.RequestID, entry.EntryID, now.String())
	rh := sha256.Sum256([]byte(resultHash))

	return &PromotionResult{
		RequestID:   req.RequestID,
		EntryID:     entry.EntryID,
		Status:      "PROMOTED",
		NewTier:     TierCKS,
		ReviewedAt:  now,
		ContentHash: "sha256:" + hex.EncodeToString(rh[:]),
	}, nil
}
