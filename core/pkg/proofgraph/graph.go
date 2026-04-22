package proofgraph

import (
	"fmt"
	"sync"
	"time"
)

// Graph is an in-memory ProofGraph DAG.
type Graph struct {
	mu      sync.RWMutex
	nodes   map[string]*Node
	heads   []string // Current head node IDs (tips of the DAG)
	lamport uint64
	clock   func() time.Time // Authority clock per KERNEL_TCB §3
}

// NewGraph creates a new empty ProofGraph.
func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		clock: time.Now, // Default; SHOULD be overridden via WithClock
	}
}

// WithClock sets the authority clock for the graph.
// Per KERNEL_TCB §3, production graphs SHOULD use a kernel authority clock.
func (g *Graph) WithClock(clock func() time.Time) *Graph {
	g.clock = clock
	return g
}

// Append adds a node to the graph, linking it to the current heads.
// Returns the finalized node with computed hash.
func (g *Graph) Append(kind NodeType, payload []byte, principal string, seq uint64) (*Node, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.lamport++

	// Standard v1.2: Graph is a DAG. Parents are heads.
	// We don't track prevHash explicitly in new Node struct beyond parents.

	node := NewNode(kind, g.heads, payload, g.lamport, principal, seq, g.clock)
	g.nodes[node.NodeHash] = node
	g.heads = []string{node.NodeHash}

	return node, nil
}

// AppendSigned adds a signed node to the graph.
// It performs the full append-and-sign within a single lock scope to avoid
// TOCTOU races and ensures the map key + heads are updated to the final hash.
func (g *Graph) AppendSigned(kind NodeType, payload []byte, signature, principal string, seq uint64) (*Node, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.lamport++

	node := NewNode(kind, g.heads, payload, g.lamport, principal, seq, g.clock)

	// Apply signature and recompute hash before storing.
	oldHash := node.NodeHash
	node.Sig = signature
	node.NodeHash = node.ComputeNodeHash()

	// Store under final (post-signature) hash only.
	_ = oldHash // pre-signature hash is never persisted
	g.nodes[node.NodeHash] = node
	g.heads = []string{node.NodeHash}

	return node, nil
}

// Get retrieves a node by ID.
func (g *Graph) Get(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// Heads returns the current head node IDs.
func (g *Graph) Heads() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]string, len(g.heads))
	copy(result, g.heads)
	return result
}

// LamportClock returns the current Lamport clock value.
func (g *Graph) LamportClock() uint64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lamport
}

// ValidateChain walks from a node back through parents and validates hashes.
func (g *Graph) ValidateChain(nodeID string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]bool)
	return g.walkValidate(nodeID, visited)
}

func (g *Graph) walkValidate(nodeID string, visited map[string]bool) error {
	if visited[nodeID] {
		return nil
	}
	visited[nodeID] = true

	node, ok := g.nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %s not found", nodeID)
	}

	if err := node.Validate(); err != nil {
		return err
	}

	for _, pid := range node.Parents {
		if err := g.walkValidate(pid, visited); err != nil {
			return err
		}
	}

	return nil
}

// Len returns the number of nodes in the graph.
func (g *Graph) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// AllNodes returns all nodes (for serialization/export).
func (g *Graph) AllNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	return result
}
