package proofgraph

import (
	"context"
	"fmt"
)

// Store defines the persistence interface for ProofGraph nodes.
type Store interface {
	// StoreNode persists a single node.
	StoreNode(ctx context.Context, node *Node) error

	// GetNode retrieves a node by ID.
	GetNode(ctx context.Context, id string) (*Node, error)

	// GetNodesByType retrieves all nodes of a given type within a Lamport range.
	GetNodesByType(ctx context.Context, kind NodeType, fromLamport, toLamport uint64) ([]*Node, error)

	// GetChain retrieves the chain of nodes from a given node ID back to genesis.
	GetChain(ctx context.Context, nodeID string) ([]*Node, error)

	// GetRange retrieves nodes in a Lamport clock range (for EvidencePack export).
	GetRange(ctx context.Context, fromLamport, toLamport uint64) ([]*Node, error)
}

// InMemoryStore is a Store implementation backed by the in-memory Graph.
type InMemoryStore struct {
	graph *Graph
}

// NewInMemoryStore creates a store backed by an in-memory graph.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{graph: NewGraph()}
}

// Graph returns the underlying graph for direct access.
func (s *InMemoryStore) Graph() *Graph {
	return s.graph
}

func (s *InMemoryStore) StoreNode(ctx context.Context, node *Node) error {
	s.graph.mu.Lock()
	defer s.graph.mu.Unlock()
	s.graph.nodes[node.NodeHash] = node
	s.graph.heads = []string{node.NodeHash}
	if node.Lamport > s.graph.lamport {
		s.graph.lamport = node.Lamport
	}
	return nil
}

func (s *InMemoryStore) GetNode(ctx context.Context, id string) (*Node, error) {
	n, ok := s.graph.Get(id)
	if !ok {
		return nil, fmt.Errorf("node %s not found", id)
	}
	return n, nil
}

func (s *InMemoryStore) GetNodesByType(ctx context.Context, kind NodeType, fromLamport, toLamport uint64) ([]*Node, error) {
	s.graph.mu.RLock()
	defer s.graph.mu.RUnlock()

	var result []*Node
	for _, n := range s.graph.nodes {
		if n.Kind == kind && n.Lamport >= fromLamport && n.Lamport <= toLamport {
			result = append(result, n)
		}
	}
	return result, nil
}

func (s *InMemoryStore) GetChain(ctx context.Context, nodeID string) ([]*Node, error) {
	s.graph.mu.RLock()
	defer s.graph.mu.RUnlock()

	var chain []*Node
	visited := make(map[string]bool)
	queue := []string{nodeID}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true

		n, ok := s.graph.nodes[id]
		if !ok {
			continue
		}
		chain = append(chain, n)
		queue = append(queue, n.Parents...)
	}
	return chain, nil
}

func (s *InMemoryStore) GetRange(ctx context.Context, fromLamport, toLamport uint64) ([]*Node, error) {
	s.graph.mu.RLock()
	defer s.graph.mu.RUnlock()

	var result []*Node
	for _, n := range s.graph.nodes {
		if n.Lamport >= fromLamport && n.Lamport <= toLamport {
			result = append(result, n)
		}
	}
	return result, nil
}
