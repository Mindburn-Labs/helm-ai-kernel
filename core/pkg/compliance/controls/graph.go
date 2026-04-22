// Package controls provides the ControlsGraph — a directed graph linking
// obligations, controls, evidence types, checks, and compensating controls.
package controls

import (
	"fmt"
	"sync"
)

// NodeType identifies node categories in the ControlsGraph.
type NodeType string

const (
	NodeObligation          NodeType = "OBLIGATION"
	NodeControl             NodeType = "CONTROL"
	NodeEvidenceType        NodeType = "EVIDENCE_TYPE"
	NodeCheck               NodeType = "CHECK"
	NodeCompensatingControl NodeType = "COMPENSATING_CONTROL"
)

// EdgeType identifies edge categories in the ControlsGraph.
type EdgeType string

const (
	EdgeSatisfies    EdgeType = "SATISFIES"      // Control → Obligation
	EdgeRequires     EdgeType = "REQUIRES"       // Obligation → EvidenceType
	EdgeProves       EdgeType = "PROVES"         // EvidenceType → Check
	EdgeMitigates    EdgeType = "MITIGATES"      // CompensatingControl → Obligation
	EdgeConflictWith EdgeType = "CONFLICTS_WITH" // Cross-control conflict
)

// Node is a vertex in the ControlsGraph.
type Node struct {
	ID         string            `json:"id"`
	Type       NodeType          `json:"type"`
	Label      string            `json:"label"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Edge is a directed edge in the ControlsGraph.
type Edge struct {
	ID         string            `json:"id"`
	Type       EdgeType          `json:"type"`
	FromID     string            `json:"from_id"`
	ToID       string            `json:"to_id"`
	Weight     float64           `json:"weight,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// Graph is the ControlsGraph linking obligations to controls and evidence.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges map[string]*Edge
	adj   map[string][]string // node ID → edge IDs (outbound)
}

// NewGraph creates a new ControlsGraph.
func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
		adj:   make(map[string][]string),
	}
}

// AddNode adds a node to the graph.
func (g *Graph) AddNode(n *Node) error {
	if n == nil || n.ID == "" {
		return fmt.Errorf("invalid node")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = n
	return nil
}

// AddEdge adds a directed edge to the graph.
func (g *Graph) AddEdge(e *Edge) error {
	if e == nil || e.ID == "" {
		return fmt.Errorf("invalid edge")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.nodes[e.FromID]; !ok {
		return fmt.Errorf("from node %s not found", e.FromID)
	}
	if _, ok := g.nodes[e.ToID]; !ok {
		return fmt.Errorf("to node %s not found", e.ToID)
	}

	g.edges[e.ID] = e
	g.adj[e.FromID] = append(g.adj[e.FromID], e.ID)
	return nil
}

// GetNode retrieves a node by ID.
func (g *Graph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// GetOutbound returns all edges leaving a node.
func (g *Graph) GetOutbound(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edgeIDs := g.adj[nodeID]
	result := make([]*Edge, 0, len(edgeIDs))
	for _, eid := range edgeIDs {
		if e, ok := g.edges[eid]; ok {
			result = append(result, e)
		}
	}
	return result
}

// FindSatisfyingControls returns all controls that satisfy an obligation.
func (g *Graph) FindSatisfyingControls(obligationID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*Node
	for _, e := range g.edges {
		if e.Type == EdgeSatisfies && e.ToID == obligationID {
			if n, ok := g.nodes[e.FromID]; ok {
				result = append(result, n)
			}
		}
	}
	return result
}

// FindRequiredEvidence returns evidence types required by an obligation.
func (g *Graph) FindRequiredEvidence(obligationID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*Node
	edgeIDs := g.adj[obligationID]
	for _, eid := range edgeIDs {
		if e, ok := g.edges[eid]; ok && e.Type == EdgeRequires {
			if n, ok := g.nodes[e.ToID]; ok {
				result = append(result, n)
			}
		}
	}
	return result
}

// FindConflicts returns all conflict edges in the graph.
func (g *Graph) FindConflicts() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*Edge
	for _, e := range g.edges {
		if e.Type == EdgeConflictWith {
			result = append(result, e)
		}
	}
	return result
}

// Stats returns graph statistics.
func (g *Graph) Stats() (nodes, edges int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes), len(g.edges)
}
