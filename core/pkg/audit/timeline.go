// Package audit — Timeline reconstruction.
//
// Per HELM 2030 Spec §5.3:
//
//	Audit timeline reconstruction assembles a chronological view
//	of all governance-relevant events for forensic analysis.
//
// Resolves: GAP-10.
package audit

import (
	"sort"
	"time"
)

// TLEventKind classifies timeline events (prefixed to avoid collision with audit.EventType).
type TLEventKind string

const (
	TLEventDecision   TLEventKind = "DECISION"
	TLEventExecution  TLEventKind = "EXECUTION"
	TLEventApproval   TLEventKind = "APPROVAL"
	TLEventDenial     TLEventKind = "DENIAL"
	TLEventEscalation TLEventKind = "ESCALATION"
	TLEventSpend      TLEventKind = "SPEND"
	TLEventPolicy     TLEventKind = "POLICY_CHANGE"
	TLEventDispute    TLEventKind = "DISPUTE"
)

// TimelineEvent is a single event in the audit timeline.
type TimelineEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      TLEventKind `json:"type"`
	ActorID   string            `json:"actor_id"`
	RunID     string            `json:"run_id,omitempty"`
	Summary   string            `json:"summary"`
	Evidence  []string          `json:"evidence_refs,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Timeline is a reconstructed chronological audit record.
type Timeline struct {
	TenantID string          `json:"tenant_id"`
	From     time.Time       `json:"from"`
	To       time.Time       `json:"to"`
	Events   []TimelineEvent `json:"events"`
}

// NewTimeline creates an empty timeline for a period.
func NewTimeline(tenantID string, from, to time.Time) *Timeline {
	return &Timeline{
		TenantID: tenantID,
		From:     from,
		To:       to,
		Events:   []TimelineEvent{},
	}
}

// Add inserts an event and keeps the timeline sorted.
func (t *Timeline) Add(event TimelineEvent) {
	t.Events = append(t.Events, event)
	sort.Slice(t.Events, func(i, j int) bool {
		return t.Events[i].Timestamp.Before(t.Events[j].Timestamp)
	})
}

// Filter returns events matching a given type.
func (t *Timeline) Filter(eventType TLEventKind) []TimelineEvent {
	var filtered []TimelineEvent
	for _, e := range t.Events {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// ForActor returns events for a specific actor.
func (t *Timeline) ForActor(actorID string) []TimelineEvent {
	var filtered []TimelineEvent
	for _, e := range t.Events {
		if e.ActorID == actorID {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// ForRun returns events for a specific run.
func (t *Timeline) ForRun(runID string) []TimelineEvent {
	var filtered []TimelineEvent
	for _, e := range t.Events {
		if e.RunID == runID {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
