package crdt

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// DistributedStore wraps a GSet and implements the proofgraph.Store interface.
// It provides a distributed, eventually-consistent store for ProofGraph nodes.
type DistributedStore struct {
	gset *GSet
}

// NewDistributedStore creates a new DistributedStore backed by a GSet.
func NewDistributedStore() *DistributedStore {
	return &DistributedStore{
		gset: NewGSet(),
	}
}

// NewDistributedStoreWithGSet creates a DistributedStore sharing an existing GSet.
// This allows the store and sync protocol to operate on the same data.
func NewDistributedStoreWithGSet(gset *GSet) *DistributedStore {
	return &DistributedStore{gset: gset}
}

// GSet returns the underlying GSet for use with the sync protocol.
func (d *DistributedStore) GSet() *GSet {
	return d.gset
}

// StoreNode persists a single node into the GSet.
func (d *DistributedStore) StoreNode(_ context.Context, node *proofgraph.Node) error {
	return d.gset.Add(node)
}

// GetNode retrieves a node by ID (hash).
func (d *DistributedStore) GetNode(_ context.Context, id string) (*proofgraph.Node, error) {
	n, ok := d.gset.Get(id)
	if !ok {
		return nil, fmt.Errorf("node %s not found", id)
	}
	return n, nil
}

// GetNodesByType retrieves all nodes of a given type within a Lamport range.
func (d *DistributedStore) GetNodesByType(_ context.Context, kind proofgraph.NodeType, fromLamport, toLamport uint64) ([]*proofgraph.Node, error) {
	all := d.gset.All()
	var result []*proofgraph.Node
	for _, n := range all {
		if n.Kind == kind && n.Lamport >= fromLamport && n.Lamport <= toLamport {
			result = append(result, n)
		}
	}
	return result, nil
}

// GetChain retrieves the chain of nodes from a given node ID back to genesis
// via a breadth-first traversal of parent links.
func (d *DistributedStore) GetChain(_ context.Context, nodeID string) ([]*proofgraph.Node, error) {
	var chain []*proofgraph.Node
	visited := make(map[string]bool)
	queue := []string{nodeID}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true

		n, ok := d.gset.Get(id)
		if !ok {
			continue
		}
		chain = append(chain, n)
		queue = append(queue, n.Parents...)
	}
	return chain, nil
}

// GetRange retrieves nodes in a Lamport clock range.
func (d *DistributedStore) GetRange(_ context.Context, fromLamport, toLamport uint64) ([]*proofgraph.Node, error) {
	all := d.gset.All()
	var result []*proofgraph.Node
	for _, n := range all {
		if n.Lamport >= fromLamport && n.Lamport <= toLamport {
			result = append(result, n)
		}
	}
	return result, nil
}

// Verify interface compliance at compile time.
var _ proofgraph.Store = (*DistributedStore)(nil)
