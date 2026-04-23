package pdp

import (
	"errors"
	"time"
)

// PDPResponse represents the decision output.
type PDPResponse struct {
	Decision        string         `json:"decision"` // ALLOW, DENY, DEFER
	DeferReasonCode string         `json:"defer_reason_code,omitempty"`
	RequiredFacts   []FactRef      `json:"required_facts,omitempty"`
	TimeoutPolicy   *TimeoutPolicy `json:"timeout_policy,omitempty"`
	RequeryRule     *RequeryRule   `json:"requery_rule,omitempty"`
}

type FactRef struct {
	FactType   string    `json:"fact_type"`
	FactID     string    `json:"fact_id"`
	RequiredBy time.Time `json:"required_by"`
}

type TimeoutPolicy struct {
	PolicyID          string `json:"policy_id"`
	TimeoutDurationMs int64  `json:"timeout_duration_ms"`
	TimeoutAction     string `json:"timeout_action"` // FAIL_CLOSED, ESCALATE_TO_HUMAN, etc.
}

type RequeryRule struct {
	Mode              string `json:"mode"` // EXACT_REUSE, DERIVED_QUERY
	OriginalQueryHash string `json:"original_query_hash"`
}

// TimeoutResult contains the outcome of a timeout check.
type TimeoutResult struct {
	Expired     bool
	Action      string
	RemainingMs int64
}

// ObligationState represents the state for timeout checking.
type ObligationState struct {
	EnteredAt time.Time
}

// ValidateDEFERResponse checks if a DEFER response is valid per Addendum 9.5.X.
func ValidateDEFERResponse(resp PDPResponse) error {
	if resp.Decision != "DEFER" {
		return nil
	}

	if resp.DeferReasonCode == "" {
		return errors.New("DEFER requires defer_reason_code")
	}

	if len(resp.RequiredFacts) == 0 {
		return errors.New("DEFER requires at least one required_fact")
	}

	if resp.TimeoutPolicy == nil {
		return errors.New("DEFER requires timeout_policy")
	}

	if resp.RequeryRule == nil {
		return errors.New("DEFER requires requery_rule")
	}

	return nil
}

// CheckTimeout performs a deterministic timeout check.
func CheckTimeout(state ObligationState, policy TimeoutPolicy, now time.Time) TimeoutResult {
	// 'now' comes from committed_at of the latest event, NOT wall clock
	deadline := state.EnteredAt.Add(time.Duration(policy.TimeoutDurationMs) * time.Millisecond)

	if now.After(deadline) {
		return TimeoutResult{
			Expired: true,
			Action:  policy.TimeoutAction,
		}
	}

	return TimeoutResult{
		Expired:     false,
		RemainingMs: deadline.Sub(now).Milliseconds(),
	}
}
