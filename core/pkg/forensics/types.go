// Package forensics defines the public contracts for HELM audit forensics.
//
// Forensics provides primitives for post-hoc analysis of execution chains:
// event graph reconstruction, denial trace analysis, and causal reasoning
// over receipt chains. This OSS package defines the type contracts and
// export interfaces. The commercial HELM Platform provides the full
// forensics engine with enterprise search and visualization.
package forensics

import "time"

// EventType classifies a forensic event.
type EventType string

const (
	EventTypeDecision     EventType = "DECISION"
	EventTypeExecution    EventType = "EXECUTION"
	EventTypeDenial       EventType = "DENIAL"
	EventTypeIntervention EventType = "INTERVENTION"
	EventTypeEscalation   EventType = "ESCALATION"
)

// ForensicEvent is a single node in the forensic event graph.
type ForensicEvent struct {
	EventID     string         `json:"event_id"`
	Type        EventType      `json:"type"`
	Timestamp   time.Time      `json:"timestamp"`
	PrincipalID string         `json:"principal_id"`
	ReceiptRef  string         `json:"receipt_ref,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	CausalChain []string       `json:"causal_chain,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	ContentHash string         `json:"content_hash"`
}

// DenialTrace captures the full analysis of why an execution was denied.
type DenialTrace struct {
	TraceID     string          `json:"trace_id"`
	RequestID   string          `json:"request_id"`
	DeniedAt    time.Time       `json:"denied_at"`
	ReasonCodes []string        `json:"reason_codes"`
	PolicyRefs  []string        `json:"policy_refs"`
	CausalPath  []ForensicEvent `json:"causal_path"`
	Remediation []string        `json:"remediation,omitempty"`
}

// EventGraph is a directed acyclic graph of forensic events.
type EventGraph struct {
	RootEventID string          `json:"root_event_id"`
	Events      []ForensicEvent `json:"events"`
	Edges       []CausalEdge    `json:"edges"`
}

// CausalEdge links two events in a causal relationship.
type CausalEdge struct {
	FromEventID string `json:"from_event_id"`
	ToEventID   string `json:"to_event_id"`
	Relation    string `json:"relation"` // "CAUSED", "TRIGGERED", "BLOCKED"
}

// Exporter is the interface for extracting forensic data.
type Exporter interface {
	ExportDenialTrace(requestID string) (*DenialTrace, error)
	ExportEventGraph(rootEventID string) (*EventGraph, error)
}
