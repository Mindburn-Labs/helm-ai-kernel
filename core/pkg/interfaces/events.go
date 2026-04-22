package interfaces

import (
	"context"
	"time"
)

// Event is the immutable unit of history.
// Corresponds to L0/EventHistoryEvent.md
// Moved from apps/data-plane/events to ensure TCB sovereignty.
type Event struct {
	SequenceID  int64       `json:"sequence_id"`
	EventType   string      `json:"event_type"`
	Timestamp   time.Time   `json:"timestamp"`
	ActorID     string      `json:"actor_id"`
	Payload     interface{} `json:"payload"`
	PayloadHash string      `json:"payload_hash"`
	PrevHash    string      `json:"prev_hash"`
	TraceID     string      `json:"trace_id,omitempty"`
}

// EventRepository defines the append-only log interface.
type EventRepository interface {
	// Append adds a new event to the history.
	Append(ctx context.Context, eventType, actorID string, payload interface{}) (*Event, error)

	// ReadFrom reads events starting from a sequence ID (inclusive).
	ReadFrom(ctx context.Context, startSequenceID int64, limit int) ([]Event, error)
}
