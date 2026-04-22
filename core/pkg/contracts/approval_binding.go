package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// ApprovalBinding ties a human approval to a specific plan version via
// content-addressed hashing. If the plan changes after approval, the
// binding becomes invalid (drift detection).
//
// Security invariant: the approval is ONLY valid for the exact PlanHash
// it was bound to. Any mutation to the plan invalidates the binding.
type ApprovalBinding struct {
	// BindingID uniquely identifies this binding.
	BindingID string `json:"binding_id"`

	// PlanHash is the SHA-256 of the serialized execution plan (PlanIR).
	PlanHash string `json:"plan_hash"`

	// ApprovalID references the approval that authorized this plan.
	ApprovalID string `json:"approval_id"`

	// BoundAt is when the binding was created.
	BoundAt time.Time `json:"bound_at"`

	// ValidUntil is the binding expiry. Plans must execute before this time.
	ValidUntil time.Time `json:"valid_until"`

	// Drifted is set to true if the plan has been modified after binding.
	Drifted bool `json:"drifted"`

	// DriftReason records why the binding was invalidated.
	DriftReason string `json:"drift_reason,omitempty"`
}

// NewApprovalBinding creates a binding between a plan hash and an approval.
func NewApprovalBinding(bindingID, planHash, approvalID string, validFor time.Duration) *ApprovalBinding {
	now := time.Now().UTC()
	return &ApprovalBinding{
		BindingID:  bindingID,
		PlanHash:   planHash,
		ApprovalID: approvalID,
		BoundAt:    now,
		ValidUntil: now.Add(validFor),
	}
}

// CheckDrift verifies that the current plan hash matches the bound hash.
// If it doesn't match, the binding is marked as drifted and invalidated.
func (ab *ApprovalBinding) CheckDrift(currentPlanHash string) bool {
	if ab.PlanHash != currentPlanHash {
		ab.Drifted = true
		ab.DriftReason = fmt.Sprintf("plan hash changed: bound=%s, current=%s", ab.PlanHash, currentPlanHash)
		return true
	}
	return false
}

// IsValid returns true if the binding is not drifted and not expired.
func (ab *ApprovalBinding) IsValid(now time.Time) bool {
	if ab.Drifted {
		return false
	}
	if now.After(ab.ValidUntil) {
		return false
	}
	return true
}

// HashPlan computes a deterministic SHA-256 hash of any plan-like struct.
// DRIFT-4 FIX: Uses RFC 8785 JCS for deterministic canonical serialization.
func HashPlan(plan interface{}) (string, error) {
	data, err := canonicalize.JCS(plan)
	if err != nil {
		return "", fmt.Errorf("approval_binding: cannot hash plan: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
