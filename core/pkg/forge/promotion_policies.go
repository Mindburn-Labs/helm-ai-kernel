package forge

import (
	"fmt"
	"time"
)

// PromotionPolicy specifies the automated and human-approval requirements for
// promoting a skill candidate by self-mod class.
type PromotionPolicy struct {
	PolicyID         string `json:"policy_id"`
	SelfModClass     string `json:"self_mod_class"`
	RequireCanary    bool   `json:"require_canary"`
	MinCanaryMinutes int    `json:"min_canary_minutes"` // 0 means no minimum soak time
	MinCanaryPct     int    `json:"min_canary_pct"`     // rollout % that must be reached
	RequireApproval  bool   `json:"require_approval"`
	MinApprovers     int    `json:"min_approvers"` // 0 when RequireApproval is false
}

// DefaultPromotionPolicies returns the built-in promotion policies for each
// self-mod class.  A fresh slice is returned on each call; callers must not
// mutate the elements.
func DefaultPromotionPolicies() []PromotionPolicy {
	return []PromotionPolicy{
		{
			PolicyID:         "policy-c0",
			SelfModClass:     "C0",
			RequireCanary:    false,
			MinCanaryMinutes: 0,
			MinCanaryPct:     0,
			RequireApproval:  false,
			MinApprovers:     0,
		},
		{
			PolicyID:         "policy-c1",
			SelfModClass:     "C1",
			RequireCanary:    true,
			MinCanaryMinutes: 10,
			MinCanaryPct:     25,
			RequireApproval:  true,
			MinApprovers:     1,
		},
		{
			PolicyID:         "policy-c2",
			SelfModClass:     "C2",
			RequireCanary:    true,
			MinCanaryMinutes: 30,
			MinCanaryPct:     50,
			RequireApproval:  true,
			MinApprovers:     1,
		},
		{
			PolicyID:         "policy-c3",
			SelfModClass:     "C3",
			RequireCanary:    true,
			MinCanaryMinutes: 60,
			MinCanaryPct:     100,
			RequireApproval:  true,
			MinApprovers:     2,
		},
	}
}

// GetPromotionPolicy returns the default policy for the given self-mod class.
// Returns an error for unknown classes — fail-closed.
func GetPromotionPolicy(selfModClass string) (*PromotionPolicy, error) {
	for _, p := range DefaultPromotionPolicies() {
		if p.SelfModClass == selfModClass {
			cp := p
			return &cp, nil
		}
	}
	return nil, fmt.Errorf(
		"forge: unknown self-mod class %q — must be one of C0, C1, C2, C3", selfModClass,
	)
}

// CanPromote evaluates whether a candidate satisfies all requirements defined
// by its policy.  It returns (true, "") when every gate is met, or
// (false, reason) explaining the first unmet gate.
//
// Parameters:
//   - candidate      — the skill candidate being considered for promotion
//   - evidence       — canary metrics, required when policy.RequireCanary is true
//   - policy         — the applicable promotion policy
//   - approvalCount  — number of human approvals already recorded
//   - canaryAge      — duration the canary has been running (used for MinCanaryMinutes)
func CanPromote(
	candidate Candidate,
	evidence *CanaryEvidence,
	policy PromotionPolicy,
	approvalCount int,
	canaryAge time.Duration,
) (bool, string) {
	// Candidate must be in CandidateReady state.
	if candidate.Status != CandidateReady {
		return false, fmt.Sprintf(
			"forge: candidate status is %q; must be %q before promotion",
			candidate.Status,
			CandidateReady,
		)
	}

	// Self-mod class must match the policy.
	if candidate.SelfModClass != policy.SelfModClass {
		return false, fmt.Sprintf(
			"forge: candidate self-mod class %q does not match policy class %q",
			candidate.SelfModClass,
			policy.SelfModClass,
		)
	}

	// Canary requirements.
	if policy.RequireCanary {
		if evidence == nil {
			return false, fmt.Sprintf(
				"forge: policy %s requires canary evidence but none provided",
				policy.PolicyID,
			)
		}

		// Ensure canary evidence belongs to this candidate.
		if evidence.CandidateID != candidate.CandidateID {
			return false, fmt.Sprintf(
				"forge: canary evidence is for candidate %q, not %q",
				evidence.CandidateID,
				candidate.CandidateID,
			)
		}

		// Rollout percentage.
		if evidence.RolloutPct < policy.MinCanaryPct {
			return false, fmt.Sprintf(
				"forge: canary rollout %d%% < required %d%%",
				evidence.RolloutPct,
				policy.MinCanaryPct,
			)
		}

		// Minimum soak time.
		minAge := time.Duration(policy.MinCanaryMinutes) * time.Minute
		if minAge > 0 && canaryAge < minAge {
			return false, fmt.Sprintf(
				"forge: canary has been running for %s; minimum required is %s",
				canaryAge.Round(time.Second),
				minAge,
			)
		}

		// Escalation check — if the canary would trigger a rollback, deny promotion.
		if escalate, reason := ShouldEscalate(evidence); escalate {
			return false, fmt.Sprintf("forge: canary escalation blocks promotion: %s", reason)
		}
	}

	// Human approval requirements.
	if policy.RequireApproval && approvalCount < policy.MinApprovers {
		return false, fmt.Sprintf(
			"forge: policy %s requires %d approver(s); only %d provided",
			policy.PolicyID,
			policy.MinApprovers,
			approvalCount,
		)
	}

	return true, ""
}
