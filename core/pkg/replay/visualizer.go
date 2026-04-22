// Package replay — Replay visualizer for evidence reconstruction.
//
// Per HELM 2030 Spec §5.3:
//
//	HELM MUST include a replay visualizer that reconstructs the audit
//	timeline and decision lineage from receipts and ProofGraph.
//
// Resolves: GAP-A4.
package replay

import (
	"fmt"
	"sort"
	"time"
)

// ── Replay Visualizer ────────────────────────────────────────────

// TimelineView is a reconstructed view of execution history.
type TimelineView struct {
	ViewID     string          `json:"view_id"`
	StartTime  time.Time       `json:"start_time"`
	EndTime    time.Time        `json:"end_time"`
	Events     []TimelineEvent  `json:"events"`
	Summary    TimelineSummary  `json:"summary"`
}

// TimelineEvent is a single event in the replay timeline.
type TimelineEvent struct {
	EventID    string            `json:"event_id"`
	Timestamp  time.Time         `json:"timestamp"`
	Type       TimelineEventType `json:"type"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Target     string            `json:"target,omitempty"`
	Verdict    string            `json:"verdict"` // "ALLOW", "DENY", "ESCALATE"
	ReasonCode string            `json:"reason_code,omitempty"`
	ReceiptID  string            `json:"receipt_id,omitempty"`
	ParentID   string            `json:"parent_id,omitempty"`  // delegation chain
	Depth      int               `json:"depth"`                // nesting depth
	Tags       map[string]string `json:"tags,omitempty"`
}

// TimelineEventType classifies events in the replay timeline.
type TimelineEventType string

const (
	EventTypeDecision    TimelineEventType = "DECISION"
	EventTypeDelegation  TimelineEventType = "DELEGATION"
	EventTypeEffect      TimelineEventType = "EFFECT"
	EventTypeApproval    TimelineEventType = "APPROVAL"
	EventTypeEscalation  TimelineEventType = "ESCALATION"
	EventTypeCheckpoint  TimelineEventType = "CHECKPOINT"
	EventTypeError       TimelineEventType = "ERROR"
)

// TimelineSummary summarizes a timeline view.
type TimelineSummary struct {
	TotalEvents   int            `json:"total_events"`
	Decisions     int            `json:"decisions"`
	Denials       int            `json:"denials"`
	Delegations   int            `json:"delegations"`
	Effects       int            `json:"effects"`
	Errors        int            `json:"errors"`
	UniqueActors  int            `json:"unique_actors"`
	MaxDepth      int            `json:"max_depth"`
	ReasonCodes   map[string]int `json:"reason_codes"`
}

// DecisionLineage reconstructs the chain of decisions that led to an outcome.
type DecisionLineage struct {
	LineageID  string           `json:"lineage_id"`
	RootEvent  string           `json:"root_event_id"`
	LeafEvent  string           `json:"leaf_event_id"`
	Path       []LineageNode    `json:"path"`
	TotalDepth int              `json:"total_depth"`
}

// LineageNode is a single node in a decision lineage.
type LineageNode struct {
	EventID    string            `json:"event_id"`
	Timestamp  time.Time         `json:"timestamp"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Verdict    string            `json:"verdict"`
	ReasonCode string            `json:"reason_code,omitempty"`
	Depth      int               `json:"depth"`
}

// BuildTimeline constructs a TimelineView from a set of receipts.
func BuildTimeline(viewID string, receipts []Receipt) (*TimelineView, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("no receipts to visualize")
	}

	events := make([]TimelineEvent, 0, len(receipts))
	for _, r := range receipts {
		ts, _ := time.Parse(time.RFC3339, r.Timestamp)
		evt := TimelineEvent{
			EventID:    r.ID,
			Timestamp:  ts,
			Type:       classifyEvent(r),
			Actor:      "", // derived from receipt context
			Action:     r.ToolName,
			Verdict:    r.Status,
			ReasonCode: r.ReasonCode,
			ReceiptID:  r.ID,
			Depth:      0,
		}
		events = append(events, evt)
	}

	// Sort by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	summary := computeSummary(events)

	var start, end time.Time
	if len(events) > 0 {
		start = events[0].Timestamp
		end = events[len(events)-1].Timestamp
	}

	return &TimelineView{
		ViewID:    viewID,
		StartTime: start,
		EndTime:   end,
		Events:    events,
		Summary:   summary,
	}, nil
}

// TraceLineage reconstructs the decision lineage from a leaf event.
func TraceLineage(lineageID string, events []TimelineEvent, leafEventID string) (*DecisionLineage, error) {
	eventMap := make(map[string]TimelineEvent, len(events))
	for _, e := range events {
		eventMap[e.EventID] = e
	}

	leaf, ok := eventMap[leafEventID]
	if !ok {
		return nil, fmt.Errorf("leaf event %s not found", leafEventID)
	}

	path := []LineageNode{{
		EventID:    leaf.EventID,
		Timestamp:  leaf.Timestamp,
		Actor:      leaf.Actor,
		Action:     leaf.Action,
		Verdict:    leaf.Verdict,
		ReasonCode: leaf.ReasonCode,
		Depth:      leaf.Depth,
	}}

	// Walk up parent chain
	current := leaf
	for current.ParentID != "" {
		parent, found := eventMap[current.ParentID]
		if !found {
			break
		}
		path = append([]LineageNode{{
			EventID:    parent.EventID,
			Timestamp:  parent.Timestamp,
			Actor:      parent.Actor,
			Action:     parent.Action,
			Verdict:    parent.Verdict,
			ReasonCode: parent.ReasonCode,
			Depth:      parent.Depth,
		}}, path...)
		current = parent
	}

	root := path[0].EventID
	return &DecisionLineage{
		LineageID:  lineageID,
		RootEvent:  root,
		LeafEvent:  leafEventID,
		Path:       path,
		TotalDepth: len(path),
	}, nil
}

func classifyEvent(r Receipt) TimelineEventType {
	switch r.Status {
	case "DENY", "DENIED":
		return EventTypeDecision
	case "ALLOW", "ALLOWED":
		return EventTypeDecision
	case "ESCALATED":
		return EventTypeEscalation
	case "ERROR":
		return EventTypeError
	default:
		return EventTypeEffect
	}
}

func computeSummary(events []TimelineEvent) TimelineSummary {
	actors := make(map[string]bool)
	reasons := make(map[string]int)
	s := TimelineSummary{TotalEvents: len(events), ReasonCodes: reasons}

	for _, e := range events {
		if e.Actor != "" {
			actors[e.Actor] = true
		}
		if e.Depth > s.MaxDepth {
			s.MaxDepth = e.Depth
		}
		if e.ReasonCode != "" {
			reasons[e.ReasonCode]++
		}
		switch e.Type {
		case EventTypeDecision:
			s.Decisions++
			if e.Verdict == "DENY" || e.Verdict == "DENIED" {
				s.Denials++
			}
		case EventTypeDelegation:
			s.Delegations++
		case EventTypeEffect:
			s.Effects++
		case EventTypeError:
			s.Errors++
		}
	}
	s.UniqueActors = len(actors)
	return s
}
