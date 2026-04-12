// Package trust — behavioral.go
// Dynamic per-agent behavioral trust scoring.
//
// Per Section 6 — agents earn or lose trust based on observed behavior.
// Score is an integer in [0, 1000] mapped to five behavioral tiers.
// Normalized() returns a float64 in [0.0, 1.0] for interop with existing
// HELM trust interfaces (e.g. memory.MemoryEntry.TrustScore).

package trust

import "time"

// ── Tiers ──────────────────────────────────────────────────────

// TrustTier categorizes agents into behavioral trust levels.
type TrustTier string

const (
	TierPristine TrustTier = "PRISTINE" // 900-1000
	TierTrusted  TrustTier = "TRUSTED"  // 700-899
	TierNeutral  TrustTier = "NEUTRAL"  // 400-699
	TierSuspect  TrustTier = "SUSPECT"  // 200-399
	TierHostile  TrustTier = "HOSTILE"  // 0-199
)

// TierForScore returns the TrustTier for a given score.
func TierForScore(score int) TrustTier {
	switch {
	case score >= 900:
		return TierPristine
	case score >= 700:
		return TierTrusted
	case score >= 400:
		return TierNeutral
	case score >= 200:
		return TierSuspect
	default:
		return TierHostile
	}
}

// ── Score Events ───────────────────────────────────────────────

// ScoreEventType identifies what triggered a score change.
type ScoreEventType string

const (
	EventPolicyComply    ScoreEventType = "POLICY_COMPLY"
	EventPolicyViolate   ScoreEventType = "POLICY_VIOLATE"
	EventRateLimitHit    ScoreEventType = "RATE_LIMIT_HIT"
	EventThreatDetected  ScoreEventType = "THREAT_DETECTED"
	EventDelegationValid ScoreEventType = "DELEGATION_VALID"
	EventDelegationAbuse ScoreEventType = "DELEGATION_ABUSE"
	EventEgressBlocked   ScoreEventType = "EGRESS_BLOCKED"
	EventManualBoost     ScoreEventType = "MANUAL_BOOST"
	EventManualPenalty   ScoreEventType = "MANUAL_PENALTY"
)

// DefaultDeltas maps event types to their default score impacts.
// Good actions yield small positive deltas (+1 to +5).
// Bad actions yield larger negative deltas (-10 to -100).
// The asymmetry reflects fail-closed trust: trust is hard to earn, easy to lose.
var DefaultDeltas = map[ScoreEventType]int{
	EventPolicyComply:    2,
	EventPolicyViolate:   -25,
	EventRateLimitHit:    -15,
	EventThreatDetected:  -50,
	EventDelegationValid: 3,
	EventDelegationAbuse: -75,
	EventEgressBlocked:   -30,
	EventManualBoost:     50,
	EventManualPenalty:   -50,
}

// ScoreEvent records a single trust-affecting action.
type ScoreEvent struct {
	EventType ScoreEventType `json:"event_type"`
	Delta     int            `json:"delta"`     // positive or negative score change
	Reason    string         `json:"reason"`    // human-readable explanation
	Timestamp time.Time      `json:"timestamp"`
}

// ── Behavioral Trust Score ─────────────────────────────────────

// BehavioralTrustScore represents the dynamic trust state of an agent.
type BehavioralTrustScore struct {
	AgentID   string       `json:"agent_id"`
	Score     int          `json:"score"` // 0-1000
	Tier      TrustTier    `json:"tier"`
	UpdatedAt time.Time    `json:"updated_at"`
	History   []ScoreEvent `json:"history"` // recent events (FIFO bounded list, keeps last N)
}

// Normalized returns the score as a float64 in [0.0, 1.0] for integration
// with existing HELM trust interfaces that use float64.
func (b *BehavioralTrustScore) Normalized() float64 {
	return float64(b.Score) / 1000.0
}
