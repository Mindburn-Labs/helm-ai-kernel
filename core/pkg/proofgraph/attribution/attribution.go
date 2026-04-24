// Package attribution implements causal fault attribution for multi-agent
// failures using the ProofGraph. When a failure occurs, it traces the causal
// chain and distributes responsibility scores from causal contribution.
//
// Design invariants:
//   - Attribution is computed from ProofGraph causal structure
//   - Each agent's score is proportional to their causal contribution
//   - Scores sum to 1.0 for a given failure
//   - Thread-safe (operates on immutable graph snapshots)
//   - No external dependencies beyond proofgraph
package attribution

import (
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// AgentContribution describes a single agent's responsibility for a failure,
// computed from causal analysis of the ProofGraph.
type AgentContribution struct {
	// Principal is the agent identifier (e.g., "user:alice", "agent:planner").
	Principal string `json:"principal"`
	// Score is the fractional responsibility, in [0.0, 1.0]. Scores sum to 1.0
	// across all agents for a given failure.
	Score float64 `json:"score"`
	// CausalDepth is the minimum distance (in graph edges) from this agent's
	// nodes to the failure node.
	CausalDepth int `json:"causal_depth"`
	// NodeCount is the number of nodes in the causal chain attributed to this agent.
	NodeCount int `json:"node_count"`
	// EffectCount is the number of EFFECT nodes attributed to this agent.
	EffectCount int `json:"effect_count"`
}

// AttributionResult is the outcome of a causal attribution analysis.
type AttributionResult struct {
	// FailureNodeID is the ProofGraph node from which the backward trace started.
	FailureNodeID string `json:"failure_node_id"`
	// Contributions lists per-agent responsibility, sorted by score descending.
	Contributions []AgentContribution `json:"contributions"`
	// TotalNodesTraced is the count of distinct nodes visited during the trace.
	TotalNodesTraced int `json:"total_nodes_traced"`
	// MaxDepth is the deepest causal depth reached.
	MaxDepth int `json:"max_depth"`
	// ComputedAt is the wall-clock time when attribution was computed.
	ComputedAt time.Time `json:"computed_at"`
}

// Option configures optional Attributor settings.
type Option func(*Attributor)

// Attributor performs causal fault attribution on a ProofGraph.
type Attributor struct {
	clock func() time.Time
}

// ErrNodeNotFound is returned when the specified node ID does not exist in the graph.
type ErrNodeNotFound struct {
	NodeID string
}

// Error implements the error interface.
func (e *ErrNodeNotFound) Error() string {
	return fmt.Sprintf("attribution: node %q not found in graph", e.NodeID)
}

// New creates a new Attributor with the given options.
func New(opts ...Option) *Attributor {
	a := &Attributor{
		clock: time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// WithClock injects a deterministic clock for testing.
func WithClock(clock func() time.Time) Option {
	return func(a *Attributor) {
		a.clock = clock
	}
}

// principalAccum accumulates per-principal statistics during the backward trace.
type principalAccum struct {
	weightedScore float64
	nodeCount     int
	effectCount   int
	minDepth      int
}

// Attribute traces the causal chain backward from failureNodeID through parent
// links, computes per-agent contribution scores, and returns the result.
//
// Algorithm:
//  1. Walk backward from failureNodeID through parent links (BFS).
//  2. For each node, accumulate a weight of 1/(depth+1) for the node's principal
//     (closer nodes carry more responsibility).
//  3. Normalize all weights to sum to 1.0.
//  4. Sort contributions by score descending.
//
// Returns ErrNodeNotFound if failureNodeID does not exist in the graph.
func (a *Attributor) Attribute(graph *proofgraph.Graph, failureNodeID string) (*AttributionResult, error) {
	// Verify the failure node exists.
	root, ok := graph.Get(failureNodeID)
	if !ok {
		return nil, fmt.Errorf("%w", &ErrNodeNotFound{NodeID: failureNodeID})
	}

	// BFS backward through parent links.
	type queueEntry struct {
		nodeID string
		depth  int
	}

	visited := make(map[string]bool)
	accum := make(map[string]*principalAccum) // principal -> accumulator
	maxDepth := 0

	queue := []queueEntry{{nodeID: failureNodeID, depth: 0}}
	visited[failureNodeID] = true

	// Seed the root node.
	processNode := func(node *proofgraph.Node, depth int) {
		principal := node.Principal
		if principal == "" {
			principal = "<unknown>"
		}

		pa, exists := accum[principal]
		if !exists {
			pa = &principalAccum{minDepth: depth}
			accum[principal] = pa
		}

		weight := 1.0 / float64(depth+1)
		pa.weightedScore += weight
		pa.nodeCount++
		if node.Kind == proofgraph.NodeTypeEffect {
			pa.effectCount++
		}
		if depth < pa.minDepth {
			pa.minDepth = depth
		}
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	processNode(root, 0)

	for len(queue) > 0 {
		entry := queue[0]
		queue = queue[1:]

		node, nodeOK := graph.Get(entry.nodeID)
		if !nodeOK {
			continue // Parent reference to a node not in this graph snapshot; skip.
		}

		for _, parentID := range node.Parents {
			if visited[parentID] {
				continue
			}
			visited[parentID] = true

			parentNode, parentOK := graph.Get(parentID)
			if !parentOK {
				continue
			}

			parentDepth := entry.depth + 1
			processNode(parentNode, parentDepth)
			queue = append(queue, queueEntry{nodeID: parentID, depth: parentDepth})
		}
	}

	// Normalize scores to sum to 1.0.
	var totalWeight float64
	for _, pa := range accum {
		totalWeight += pa.weightedScore
	}

	contributions := make([]AgentContribution, 0, len(accum))
	for principal, pa := range accum {
		score := 0.0
		if totalWeight > 0 {
			score = pa.weightedScore / totalWeight
		}
		contributions = append(contributions, AgentContribution{
			Principal:   principal,
			Score:       score,
			CausalDepth: pa.minDepth,
			NodeCount:   pa.nodeCount,
			EffectCount: pa.effectCount,
		})
	}

	// Sort by score descending, then by principal for determinism on ties.
	sort.Slice(contributions, func(i, j int) bool {
		if contributions[i].Score != contributions[j].Score {
			return contributions[i].Score > contributions[j].Score
		}
		return contributions[i].Principal < contributions[j].Principal
	})

	return &AttributionResult{
		FailureNodeID:    failureNodeID,
		Contributions:    contributions,
		TotalNodesTraced: len(visited),
		MaxDepth:         maxDepth,
		ComputedAt:       a.clock(),
	}, nil
}
