// Package crdt implements CRDT-based distributed replication for the ProofGraph.
// Since the ProofGraph is append-only (no updates or deletes), a G-Set (Grow-Only Set)
// CRDT is sufficient. Nodes are content-addressed by their SHA-256 hash, making
// merge a simple set union with no conflict resolution needed.
package crdt

import (
	"fmt"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// GSet implements a Grow-Only Set CRDT for ProofGraph nodes.
// Nodes can only be added, never removed or updated.
// This provides eventual consistency across replicas without coordination.
type GSet struct {
	mu    sync.RWMutex
	nodes map[string]*proofgraph.Node // nodeHash -> node (content-addressed)
}

// NewGSet creates an empty G-Set.
func NewGSet() *GSet {
	return &GSet{
		nodes: make(map[string]*proofgraph.Node),
	}
}

// Add inserts a node into the set. Idempotent -- adding an existing node is a no-op.
// Returns an error if the node's hash does not match its computed hash.
func (g *GSet) Add(node *proofgraph.Node) error {
	expected, err := node.ComputeNodeHashE()
	if err != nil {
		return fmt.Errorf("crdt: hash computation failed: %w", err)
	}
	if node.NodeHash != expected {
		return fmt.Errorf("crdt: node hash mismatch: got %s, want %s", node.NodeHash, expected)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Idempotent: if already present, no-op.
	if _, exists := g.nodes[node.NodeHash]; exists {
		return nil
	}

	g.nodes[node.NodeHash] = node
	return nil
}

// Contains checks if a node hash is in the set.
func (g *GSet) Contains(nodeHash string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.nodes[nodeHash]
	return ok
}

// Get retrieves a node by hash.
func (g *GSet) Get(nodeHash string) (*proofgraph.Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[nodeHash]
	return n, ok
}

// Len returns the number of nodes.
func (g *GSet) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// All returns all nodes as a snapshot.
func (g *GSet) All() []*proofgraph.Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make([]*proofgraph.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	return result
}

// Hashes returns all node hashes as a snapshot.
func (g *GSet) Hashes() map[string]bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	result := make(map[string]bool, len(g.nodes))
	for h := range g.nodes {
		result[h] = true
	}
	return result
}

// Merge combines another GSet into this one (union). Returns nodes that were new.
// Thread-safe on both sets.
func (g *GSet) Merge(other *GSet) []*proofgraph.Node {
	// Take a snapshot of the other set first to avoid nested locks.
	otherNodes := other.All()

	g.mu.Lock()
	defer g.mu.Unlock()

	var added []*proofgraph.Node
	for _, n := range otherNodes {
		if _, exists := g.nodes[n.NodeHash]; !exists {
			g.nodes[n.NodeHash] = n
			added = append(added, n)
		}
	}
	return added
}

// Delta returns nodes in this set that are NOT in the other set (identified by hash).
// Used for efficient sync: send only what the peer does not have.
func (g *GSet) Delta(otherHashes map[string]bool) []*proofgraph.Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var missing []*proofgraph.Node
	for h, n := range g.nodes {
		if !otherHashes[h] {
			missing = append(missing, n)
		}
	}
	return missing
}
