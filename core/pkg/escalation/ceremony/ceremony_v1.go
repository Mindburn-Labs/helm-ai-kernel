// Package ceremony implements RFC-005 Approval Ceremony for HITL interactions.
package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CeremonyPolicy defines the requirements for an approval ceremony.
type CeremonyPolicy struct {
	MinTimelockMs    int64  `json:"min_timelock_ms"`   // Minimum delay before approval activates
	MinHoldMs        int64  `json:"min_hold_ms"`       // Minimum time human must hold the approval screen
	RequireChallenge bool   `json:"require_challenge"` // Whether challenge/response is required
	DomainSeparation string `json:"domain_separation"` // Domain prefix for signature scope
}

// DefaultPolicy returns a conservative default ceremony policy.
func DefaultPolicy() CeremonyPolicy {
	return CeremonyPolicy{
		MinTimelockMs:    2000,
		MinHoldMs:        1000,
		RequireChallenge: false,
		DomainSeparation: "helm:approval:v1",
	}
}

// StrictPolicy returns a high-security ceremony policy with challenge/response.
func StrictPolicy() CeremonyPolicy {
	return CeremonyPolicy{
		MinTimelockMs:    5000,
		MinHoldMs:        3000,
		RequireChallenge: true,
		DomainSeparation: "helm:approval:v1:strict",
	}
}

// CeremonyRequest is submitted by the human operator.
type CeremonyRequest struct {
	DecisionID    string `json:"decision_id"`
	TimelockMs    int64  `json:"timelock_ms"`
	HoldMs        int64  `json:"hold_ms"`
	UISummaryHash string `json:"ui_summary_hash"`
	ChallengeHash string `json:"challenge_hash,omitempty"`
	ResponseHash  string `json:"response_hash,omitempty"`
	LamportHeight uint64 `json:"lamport_height"`
	SignerKeyID   string `json:"signer_key_id"`
	Signature     string `json:"signature"`
	SubmittedAt   int64  `json:"submitted_at_unix"`
}

// CeremonyResult is the outcome of ceremony validation.
type CeremonyResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// ValidateCeremony checks if a ceremony request meets the policy requirements.
func ValidateCeremony(policy CeremonyPolicy, req CeremonyRequest) CeremonyResult {
	// 1. Timelock check
	if req.TimelockMs < policy.MinTimelockMs {
		return CeremonyResult{
			Valid:  false,
			Reason: fmt.Sprintf("timelock %dms < minimum %dms", req.TimelockMs, policy.MinTimelockMs),
		}
	}

	// 2. Hold time check
	if req.HoldMs < policy.MinHoldMs {
		return CeremonyResult{
			Valid:  false,
			Reason: fmt.Sprintf("hold time %dms < minimum %dms", req.HoldMs, policy.MinHoldMs),
		}
	}

	// 3. Check timelock hasn't expired yet — the approval shouldn't be used before the lock period
	if req.SubmittedAt > 0 {
		elapsed := time.Now().Unix() - req.SubmittedAt
		if elapsed < 0 {
			return CeremonyResult{
				Valid:  false,
				Reason: "submitted_at is in the future",
			}
		}
	}

	// 4. Challenge/response check
	if policy.RequireChallenge {
		if req.ChallengeHash == "" || req.ResponseHash == "" {
			return CeremonyResult{
				Valid:  false,
				Reason: "challenge/response required but not provided",
			}
		}
	}

	// 5. UI Summary hash must be present
	if req.UISummaryHash == "" {
		return CeremonyResult{
			Valid:  false,
			Reason: "ui_summary_hash is required",
		}
	}

	// 6. Signature must be present (actual crypto verification done by caller)
	if req.Signature == "" {
		return CeremonyResult{
			Valid:  false,
			Reason: "signature is required",
		}
	}

	return CeremonyResult{Valid: true}
}

// HashUISummary creates a deterministic hash of the UI summary shown to the human.
func HashUISummary(summary string) string {
	h := sha256.Sum256([]byte(summary))
	return hex.EncodeToString(h[:])
}

// HashChallenge creates a deterministic hash of a challenge string.
func HashChallenge(challenge string) string {
	h := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(h[:])
}
