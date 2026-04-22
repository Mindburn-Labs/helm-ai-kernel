package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ValidateGenesisApproval checks if a VGL genesis approval request meets
// the canonical requirements per ARCHITECTURE.md §3.
//
// Verification order:
//  1. All four binding hashes must be non-empty
//  2. Challenge hash must match the derivation from the four binding hashes
//  3. Timelock must be met
//  4. At least one approver signature must be present
//  5. Quorum must be satisfied (if > 0)
//  6. Rate limit window is checked externally (caller's responsibility)
func ValidateGenesisApproval(req contracts.GenesisApprovalRequest) contracts.GenesisApprovalResult {
	// 1. Binding completeness — all four hashes required
	if req.Binding.PolicyGenesisHash == "" {
		return contracts.GenesisApprovalResult{Valid: false, Reason: "policy_genesis_hash is required"}
	}
	if req.Binding.MirrorTextHash == "" {
		return contracts.GenesisApprovalResult{Valid: false, Reason: "mirror_text_hash is required"}
	}
	if req.Binding.ImpactReportHash == "" {
		return contracts.GenesisApprovalResult{Valid: false, Reason: "impact_report_hash is required"}
	}
	if req.Binding.P0CeilingHash == "" {
		return contracts.GenesisApprovalResult{Valid: false, Reason: "p0_ceiling_hash is required"}
	}

	// 2. Challenge hash derivation — must match the canonical derivation
	expectedChallenge := DeriveGenesisChallenge(req.Binding)
	if req.ChallengeHash != expectedChallenge {
		return contracts.GenesisApprovalResult{
			Valid:  false,
			Reason: fmt.Sprintf("challenge_hash mismatch: expected %s, got %s", expectedChallenge, req.ChallengeHash),
		}
	}

	// 3. Timelock — must be non-zero
	if req.TimelockDuration <= 0 {
		return contracts.GenesisApprovalResult{
			Valid:  false,
			Reason: "timelock_duration must be > 0",
		}
	}

	// 4. At least one approver
	if len(req.ApproverKeyIDs) == 0 || len(req.Signatures) == 0 {
		return contracts.GenesisApprovalResult{
			Valid:  false,
			Reason: "at least one approver key ID and signature required",
		}
	}

	// 5. Signature count must match key count
	if len(req.ApproverKeyIDs) != len(req.Signatures) {
		return contracts.GenesisApprovalResult{
			Valid:  false,
			Reason: fmt.Sprintf("approver count mismatch: %d keys, %d signatures", len(req.ApproverKeyIDs), len(req.Signatures)),
		}
	}

	// 6. Quorum check
	if req.Quorum > 0 && len(req.Signatures) < req.Quorum {
		return contracts.GenesisApprovalResult{
			Valid:  false,
			Reason: fmt.Sprintf("quorum not met: need %d, have %d", req.Quorum, len(req.Signatures)),
		}
	}

	// 7. Emergency override generates elevated risk
	activatesAt := req.SubmittedAt.Add(req.TimelockDuration).Unix()

	return contracts.GenesisApprovalResult{
		Valid:          true,
		ActivatesAt:    activatesAt,
		RequiresReview: req.EmergencyOverride,
		ElevatedRisk:   req.EmergencyOverride,
	}
}

// DeriveGenesisChallenge computes the canonical challenge hash from the
// four binding hashes. Per ARCHITECTURE.md §3: the challenge is the SHA-256
// of the concatenation of all four hashes in canonical order.
func DeriveGenesisChallenge(b contracts.GenesisApprovalBinding) string {
	h := sha256.New()
	h.Write([]byte(b.PolicyGenesisHash))
	h.Write([]byte(b.MirrorTextHash))
	h.Write([]byte(b.ImpactReportHash))
	h.Write([]byte(b.P0CeilingHash))
	return hex.EncodeToString(h.Sum(nil))
}

// TimelockRemaining returns the remaining timelock duration before
// activation is permitted. Returns 0 if the timelock has elapsed.
func TimelockRemaining(req contracts.GenesisApprovalRequest) time.Duration {
	activatesAt := req.SubmittedAt.Add(req.TimelockDuration)
	remaining := time.Until(activatesAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}
