// Package kernel provides deterministic concurrency artifacts.
// Per HELM Normative Addendum v1.5 Section F - Deterministic Concurrency Model.
package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

// ============================================================================
// Section F: Deterministic Concurrency Model
// ============================================================================

// ConcurrencyArtifactType identifies the type of concurrency artifact.
type ConcurrencyArtifactType string

const (
	// ConcurrencyArtifactDependencyGraph captures input dependencies.
	ConcurrencyArtifactDependencyGraph ConcurrencyArtifactType = "DEPENDENCY_GRAPH"
	// ConcurrencyArtifactAttemptIndex captures retry attempt tracking.
	ConcurrencyArtifactAttemptIndex ConcurrencyArtifactType = "ATTEMPT_INDEX"
	// ConcurrencyArtifactRetrySchedule captures retry scheduling.
	ConcurrencyArtifactRetrySchedule ConcurrencyArtifactType = "RETRY_SCHEDULE"
	// ConcurrencyArtifactExecutionTrace captures execution ordering.
	ConcurrencyArtifactExecutionTrace ConcurrencyArtifactType = "EXECUTION_TRACE"
)

// DependencyNode represents a node in the dependency graph.
// Per Section F.1: All concurrency influence captured as explicit artifacts.
type DependencyNode struct {
	NodeID      string   `json:"node_id"`
	NodeType    string   `json:"node_type"`
	DependsOn   []string `json:"depends_on,omitempty"`
	ProducedAt  int64    `json:"produced_at"`
	ContentHash string   `json:"content_hash"`
}

// DependencyGraph captures all input dependencies for a reducer.
// Per Section F.1: dependency_graph artifact captures scheduler influence.
type DependencyGraph struct {
	GraphID   string           `json:"graph_id"`
	ReducerID string           `json:"reducer_id"`
	CreatedAt time.Time        `json:"created_at"`
	Nodes     []DependencyNode `json:"nodes"`
	Edges     []DependencyEdge `json:"edges"`
	RootNodes []string         `json:"root_nodes"`
	LeafNodes []string         `json:"leaf_nodes"`
	Hash      string           `json:"hash"`
}

// DependencyEdge represents a dependency relationship.
type DependencyEdge struct {
	FromNode string `json:"from_node"`
	ToNode   string `json:"to_node"`
	EdgeType string `json:"edge_type"` // DATA, CONTROL, TEMPORAL
}

// NewDependencyGraph creates a new dependency graph.
func NewDependencyGraph(graphID, reducerID string) *DependencyGraph {
	return &DependencyGraph{
		GraphID:   graphID,
		ReducerID: reducerID,
		CreatedAt: time.Now().UTC(),
		Nodes:     []DependencyNode{},
		Edges:     []DependencyEdge{},
		RootNodes: []string{},
		LeafNodes: []string{},
	}
}

// AddNode adds a node to the dependency graph.
func (g *DependencyGraph) AddNode(node DependencyNode) {
	g.Nodes = append(g.Nodes, node)
}

// AddEdge adds an edge to the dependency graph.
func (g *DependencyGraph) AddEdge(fromNode, toNode, edgeType string) {
	g.Edges = append(g.Edges, DependencyEdge{
		FromNode: fromNode,
		ToNode:   toNode,
		EdgeType: edgeType,
	})
}

// Finalize computes the graph hash and identifies root/leaf nodes.
func (g *DependencyGraph) Finalize() {
	// Find root nodes (no incoming edges)
	incoming := make(map[string]bool)
	for _, e := range g.Edges {
		incoming[e.ToNode] = true
	}
	g.RootNodes = []string{}
	for _, n := range g.Nodes {
		if !incoming[n.NodeID] {
			g.RootNodes = append(g.RootNodes, n.NodeID)
		}
	}

	// Find leaf nodes (no outgoing edges)
	outgoing := make(map[string]bool)
	for _, e := range g.Edges {
		outgoing[e.FromNode] = true
	}
	g.LeafNodes = []string{}
	for _, n := range g.Nodes {
		if !outgoing[n.NodeID] {
			g.LeafNodes = append(g.LeafNodes, n.NodeID)
		}
	}

	// Sort for determinism
	sort.Strings(g.RootNodes)
	sort.Strings(g.LeafNodes)

	// Compute hash
	g.Hash = g.computeHash()
}

func (g *DependencyGraph) computeHash() string {
	// Sort nodes and edges for determinism
	nodeData := make([]map[string]any, len(g.Nodes))
	for i, n := range g.Nodes {
		nodeData[i] = map[string]any{
			"id":   n.NodeID,
			"type": n.NodeType,
			"deps": n.DependsOn,
			"hash": n.ContentHash,
		}
	}
	sort.Slice(nodeData, func(i, j int) bool {
		return nodeData[i]["id"].(string) < nodeData[j]["id"].(string)
	})

	edgeData := make([]map[string]string, len(g.Edges))
	for i, e := range g.Edges {
		edgeData[i] = map[string]string{
			"from": e.FromNode,
			"to":   e.ToNode,
			"type": e.EdgeType,
		}
	}
	sort.Slice(edgeData, func(i, j int) bool {
		if edgeData[i]["from"] != edgeData[j]["from"] {
			return edgeData[i]["from"] < edgeData[j]["from"]
		}
		return edgeData[i]["to"] < edgeData[j]["to"]
	})

	data, _ := json.Marshal(map[string]any{
		"nodes": nodeData,
		"edges": edgeData,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// AttemptIndex tracks retry attempts for deterministic replay.
// Per Section F.2: attempt_index artifact for retry tracking.
type AttemptIndex struct {
	IndexID      string         `json:"index_id"`
	OperationID  string         `json:"operation_id"`
	Attempts     []AttemptEntry `json:"attempts"`
	CurrentIndex int            `json:"current_index"`
	MaxAttempts  int            `json:"max_attempts"`
}

// AttemptEntry represents a single attempt.
type AttemptEntry struct {
	AttemptNum  int       `json:"attempt_num"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Success     bool      `json:"success"`
	ErrorCode   string    `json:"error_code,omitempty"`
	ErrorHash   string    `json:"error_hash,omitempty"`
}

// NewAttemptIndex creates a new attempt index.
func NewAttemptIndex(indexID, operationID string, maxAttempts int) *AttemptIndex {
	return &AttemptIndex{
		IndexID:      indexID,
		OperationID:  operationID,
		Attempts:     []AttemptEntry{},
		CurrentIndex: 0,
		MaxAttempts:  maxAttempts,
	}
}

// RecordAttempt records an attempt.
func (a *AttemptIndex) RecordAttempt(success bool, errorCode, errorMsg string) {
	var errorHash string
	if errorMsg != "" {
		h := sha256.Sum256([]byte(errorMsg))
		errorHash = hex.EncodeToString(h[:16])
	}

	entry := AttemptEntry{
		AttemptNum:  a.CurrentIndex + 1,
		StartedAt:   time.Now().UTC(),
		CompletedAt: time.Now().UTC(),
		Success:     success,
		ErrorCode:   errorCode,
		ErrorHash:   errorHash,
	}
	a.Attempts = append(a.Attempts, entry)
	a.CurrentIndex++
}

// CanRetry checks if more attempts are allowed.
func (a *AttemptIndex) CanRetry() bool {
	return a.CurrentIndex < a.MaxAttempts
}

// LastAttempt returns the most recent attempt.
func (a *AttemptIndex) LastAttempt() *AttemptEntry {
	if len(a.Attempts) == 0 {
		return nil
	}
	return &a.Attempts[len(a.Attempts)-1]
}

// RetrySchedule captures retry timing for deterministic replay.
// Per Section F.3: retry_schedule_ref artifact.
type RetrySchedule struct {
	ScheduleID    string        `json:"schedule_id"`
	OperationID   string        `json:"operation_id"`
	Strategy      RetryStrategy `json:"strategy"`
	BaseDelayMs   int           `json:"base_delay_ms"`
	MaxDelayMs    int           `json:"max_delay_ms"`
	Multiplier    float64       `json:"multiplier"`
	ScheduledRuns []int64       `json:"scheduled_runs"` // Unix timestamps
}

// RetryStrategy defines the retry backoff strategy.
type RetryStrategy string

const (
	RetryStrategyFixed       RetryStrategy = "FIXED"
	RetryStrategyLinear      RetryStrategy = "LINEAR"
	RetryStrategyExponential RetryStrategy = "EXPONENTIAL"
)

// NewRetrySchedule creates a new retry schedule.
func NewRetrySchedule(scheduleID, operationID string, strategy RetryStrategy, baseDelayMs, maxDelayMs int, multiplier float64) *RetrySchedule {
	return &RetrySchedule{
		ScheduleID:    scheduleID,
		OperationID:   operationID,
		Strategy:      strategy,
		BaseDelayMs:   baseDelayMs,
		MaxDelayMs:    maxDelayMs,
		Multiplier:    multiplier,
		ScheduledRuns: []int64{},
	}
}

// ComputeDelay computes the delay for a given attempt (0-indexed).
func (r *RetrySchedule) ComputeDelay(attemptIndex int) int {
	var delay int
	switch r.Strategy {
	case RetryStrategyFixed:
		delay = r.BaseDelayMs
	case RetryStrategyLinear:
		delay = r.BaseDelayMs * (attemptIndex + 1)
	case RetryStrategyExponential:
		delay = int(float64(r.BaseDelayMs) * pow(r.Multiplier, float64(attemptIndex)))
	default:
		delay = r.BaseDelayMs
	}

	if delay > r.MaxDelayMs {
		delay = r.MaxDelayMs
	}
	return delay
}

// ScheduleNextRun computes and records the next run time.
func (r *RetrySchedule) ScheduleNextRun(baseTime time.Time, attemptIndex int) time.Time {
	delayMs := r.ComputeDelay(attemptIndex)
	nextRun := baseTime.Add(time.Duration(delayMs) * time.Millisecond)
	r.ScheduledRuns = append(r.ScheduledRuns, nextRun.UnixMilli())
	return nextRun
}

// pow computes x^y for floats.
func pow(x, y float64) float64 {
	result := 1.0
	for i := 0; i < int(y); i++ {
		result *= x
	}
	return result
}

// ExecutionTrace captures the order of execution for replay.
// Per Section F.4: Execution ordering must be reproducible.
type ExecutionTrace struct {
	TraceID   string           `json:"trace_id"`
	ReducerID string           `json:"reducer_id"`
	Entries   []ExecutionEntry `json:"entries"`
	Hash      string           `json:"hash"`
}

// ExecutionEntry represents one execution step.
type ExecutionEntry struct {
	StepNum     int       `json:"step_num"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	ProcessedAt time.Time `json:"processed_at"`
	InputHash   string    `json:"input_hash"`
	OutputHash  string    `json:"output_hash"`
}

// NewExecutionTrace creates a new execution trace.
func NewExecutionTrace(traceID, reducerID string) *ExecutionTrace {
	return &ExecutionTrace{
		TraceID:   traceID,
		ReducerID: reducerID,
		Entries:   []ExecutionEntry{},
	}
}

// AddEntry adds an execution entry.
func (t *ExecutionTrace) AddEntry(eventID, eventType, inputHash, outputHash string) {
	t.Entries = append(t.Entries, ExecutionEntry{
		StepNum:     len(t.Entries) + 1,
		EventID:     eventID,
		EventType:   eventType,
		ProcessedAt: time.Now().UTC(),
		InputHash:   inputHash,
		OutputHash:  outputHash,
	})
}

// Finalize computes the trace hash.
func (t *ExecutionTrace) Finalize() {
	data, _ := json.Marshal(t.Entries)
	hash := sha256.Sum256(data)
	t.Hash = hex.EncodeToString(hash[:])
}

// VerifyDeterminism checks if two traces are identical.
func (t *ExecutionTrace) VerifyDeterminism(other *ExecutionTrace) bool {
	if len(t.Entries) != len(other.Entries) {
		return false
	}
	for i, e := range t.Entries {
		o := other.Entries[i]
		if e.EventID != o.EventID || e.EventType != o.EventType {
			return false
		}
		if e.InputHash != o.InputHash || e.OutputHash != o.OutputHash {
			return false
		}
	}
	return true
}

// ConcurrencyArtifact is a union type for all concurrency artifacts.
type ConcurrencyArtifact struct {
	Type            ConcurrencyArtifactType `json:"type"`
	DependencyGraph *DependencyGraph        `json:"dependency_graph,omitempty"`
	AttemptIndex    *AttemptIndex           `json:"attempt_index,omitempty"`
	RetrySchedule   *RetrySchedule          `json:"retry_schedule,omitempty"`
	ExecutionTrace  *ExecutionTrace         `json:"execution_trace,omitempty"`
}

// ValidateConcurrencyArtifact validates a concurrency artifact.
func ValidateConcurrencyArtifact(artifact *ConcurrencyArtifact) []string {
	issues := []string{}

	switch artifact.Type {
	case ConcurrencyArtifactDependencyGraph:
		if artifact.DependencyGraph == nil {
			issues = append(issues, "dependency_graph is nil")
		} else if artifact.DependencyGraph.Hash == "" {
			issues = append(issues, "dependency_graph hash not computed")
		}
	case ConcurrencyArtifactAttemptIndex:
		if artifact.AttemptIndex == nil {
			issues = append(issues, "attempt_index is nil")
		}
	case ConcurrencyArtifactRetrySchedule:
		if artifact.RetrySchedule == nil {
			issues = append(issues, "retry_schedule is nil")
		}
	case ConcurrencyArtifactExecutionTrace:
		if artifact.ExecutionTrace == nil {
			issues = append(issues, "execution_trace is nil")
		}
	default:
		issues = append(issues, "unknown concurrency artifact type")
	}

	return issues
}
