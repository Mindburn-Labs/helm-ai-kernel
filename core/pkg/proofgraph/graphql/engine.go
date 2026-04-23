// Package graphql provides a GraphQL query engine for the HELM ProofGraph.
package graphql

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// QueryRequest represents a ProofGraph query.
type QueryRequest struct {
	// NodeHash returns a specific node by hash.
	NodeHash string `json:"node_hash,omitempty"`

	// FromLamport filters nodes with Lamport >= this value.
	FromLamport *uint64 `json:"from_lamport,omitempty"`

	// ToLamport filters nodes with Lamport <= this value.
	ToLamport *uint64 `json:"to_lamport,omitempty"`

	// Principal filters by originating principal.
	Principal string `json:"principal,omitempty"`

	// Kind filters by node type.
	Kind string `json:"kind,omitempty"`

	// Limit caps the result count.
	Limit int `json:"limit,omitempty"`

	// IncludePayload determines whether to include full payload blobs.
	IncludePayload bool `json:"include_payload,omitempty"`
}

// QueryResponse wraps query results.
type QueryResponse struct {
	Nodes      []*NodeView `json:"nodes"`
	TotalCount int         `json:"total_count"`
}

// NodeView is a read-only projection of a ProofGraph node.
type NodeView struct {
	NodeHash  string          `json:"node_hash"`
	Parents   []string        `json:"parents,omitempty"`
	Kind      string          `json:"kind"`
	Principal string          `json:"principal"`
	Lamport   uint64          `json:"lamport"`
	Timestamp int64           `json:"timestamp"`
	Sig       string          `json:"sig,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Engine executes queries against the ProofGraph store.
type Engine struct {
	store proofgraph.Store
}

// NewEngine creates a new ProofGraph query engine.
func NewEngine(store proofgraph.Store) *Engine {
	return &Engine{store: store}
}

// Execute runs a query against the ProofGraph.
func (e *Engine) Execute(ctx context.Context, req QueryRequest) (*QueryResponse, error) {
	// Single node lookup.
	if req.NodeHash != "" {
		node, err := e.store.GetNode(ctx, req.NodeHash)
		if err != nil {
			return nil, fmt.Errorf("graphql: node %s: %w", req.NodeHash, err)
		}
		return &QueryResponse{
			Nodes:      []*NodeView{nodeToView(node, req.IncludePayload)},
			TotalCount: 1,
		}, nil
	}

	// Range query.
	var fromL, toL uint64
	if req.FromLamport != nil {
		fromL = *req.FromLamport
	}
	if req.ToLamport != nil {
		toL = *req.ToLamport
	} else {
		toL = ^uint64(0) // max
	}

	nodes, err := e.store.GetRange(ctx, fromL, toL)
	if err != nil {
		return nil, fmt.Errorf("graphql: range query: %w", err)
	}

	// Apply filters.
	var filtered []*proofgraph.Node
	for _, n := range nodes {
		if req.Principal != "" && n.Principal != req.Principal {
			continue
		}
		if req.Kind != "" && string(n.Kind) != req.Kind {
			continue
		}
		filtered = append(filtered, n)
	}

	// Apply limit.
	if req.Limit > 0 && len(filtered) > req.Limit {
		filtered = filtered[:req.Limit]
	}

	views := make([]*NodeView, len(filtered))
	for i, n := range filtered {
		views[i] = nodeToView(n, req.IncludePayload)
	}

	return &QueryResponse{
		Nodes:      views,
		TotalCount: len(views),
	}, nil
}

func nodeToView(n *proofgraph.Node, includePayload bool) *NodeView {
	v := &NodeView{
		NodeHash:  n.NodeHash,
		Parents:   n.Parents,
		Kind:      string(n.Kind),
		Principal: n.Principal,
		Lamport:   n.Lamport,
		Timestamp: n.Timestamp,
		Sig:       n.Sig,
	}
	if includePayload {
		v.Payload = n.Payload
	}
	return v
}
