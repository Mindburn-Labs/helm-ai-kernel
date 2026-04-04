// Package attention provides the People/Programs/Accounts routing layer for HELM.
//
// It matches inbound signals to watches (people, programs, accounts, incidents),
// computes attention scores, and routes signals to the appropriate entities.
// The attention layer sits between signal ingestion and the surface/action layer,
// ensuring that every signal reaches the right person or program at the right time.
package attention

import "time"

// WatchType classifies the kind of entity being watched.
type WatchType string

const (
	WatchTypePerson   WatchType = "PERSON"
	WatchTypeProgram  WatchType = "PROGRAM"
	WatchTypeAccount  WatchType = "ACCOUNT"
	WatchTypeIncident WatchType = "INCIDENT"
)

// IsValid returns true if the watch type is recognized.
func (w WatchType) IsValid() bool {
	switch w {
	case WatchTypePerson, WatchTypeProgram, WatchTypeAccount, WatchTypeIncident:
		return true
	default:
		return false
	}
}

// Watch represents a routing rule that binds an entity to topic-based signal matching.
// When an inbound signal's subject or topic matches a watch, the attention router
// computes a score and decides whether to route the signal to the watch's owner.
type Watch struct {
	// WatchID is the unique identifier for this watch.
	WatchID string `json:"watch_id"`

	// Type classifies the entity being watched.
	Type WatchType `json:"type"`

	// EntityID is the stable identifier of the watched entity.
	EntityID string `json:"entity_id"`

	// EntityName is a human-readable name for the watched entity.
	EntityName string `json:"entity_name,omitempty"`

	// Priority is the routing priority (0-100). Higher values are routed first.
	Priority int `json:"priority"`

	// TopicTags are the topics this watch matches against.
	TopicTags []string `json:"topic_tags,omitempty"`

	// OwnerID is the identity.Principal.ID() that owns this watch.
	OwnerID string `json:"owner_id"`

	// CreatedAt is when the watch was created.
	CreatedAt time.Time `json:"created_at"`

	// Metadata holds optional key-value annotations.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AttentionScore is the result of scoring a signal against a watch.
// It captures whether the signal should be routed and with what urgency.
type AttentionScore struct {
	// SignalID is the signal that was scored.
	SignalID string `json:"signal_id"`

	// WatchID is the watch that was matched.
	WatchID string `json:"watch_id"`

	// Score is the computed attention score (0.0-1.0).
	Score float64 `json:"score"`

	// Reason is a human-readable explanation of the score.
	Reason string `json:"reason"`

	// ShouldRoute indicates whether the signal should be routed to the watch owner.
	ShouldRoute bool `json:"should_route"`

	// EscalationHint is set when the score exceeds the escalation threshold.
	EscalationHint *EscalationHint `json:"escalation_hint,omitempty"`
}

// ProgramState tracks the runtime state of an attention program.
type ProgramState struct {
	// ProgramID is the unique identifier for this program.
	ProgramID string `json:"program_id"`

	// Status is the current lifecycle state.
	Status string `json:"status"`

	// AssignedTo is the identity.Principal.ID() assigned to this program.
	AssignedTo string `json:"assigned_to"`

	// TopicTags are the topics this program is interested in.
	TopicTags []string `json:"topic_tags,omitempty"`

	// LastSignalAt is when the program last received a signal.
	LastSignalAt time.Time `json:"last_signal_at"`
}

// ProgramStatus constants.
const (
	ProgramStatusActive    = "ACTIVE"
	ProgramStatusPaused    = "PAUSED"
	ProgramStatusCompleted = "COMPLETED"
	ProgramStatusFailed    = "FAILED"
)
