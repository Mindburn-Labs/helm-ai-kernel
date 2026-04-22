package contracts

import "time"

// EventEnvelope is the immutable record of a system occurrence.
// It enforces the Spine Contract: Every event has a proposal_id.
type EventEnvelope struct {
	EventID       string `json:"event_id"`
	ProposalID    string `json:"proposal_id"` // The Spine
	EventType     string `json:"event_type"`
	EventVersion  string `json:"event_version"`
	CanonicalHash string `json:"canonical_hash"`

	// Deterministic Time
	OracleTick int64     `json:"ts_oracle_tick"`
	Timestamp  time.Time `json:"timestamp"` // Wall time for human readability

	Payload        any    `json:"payload"`
	IdempotencyKey string `json:"idempotency_key"`
}
