package graphql

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func TestExecuteSingleNode(t *testing.T) {
	node := testNode("node-1", proofgraph.NodeTypeIntent, "alice", 10, `{"ok":true}`)
	engine := NewEngine(&fakeStore{node: node})

	resp, err := engine.Execute(context.Background(), QueryRequest{
		NodeHash:       "node-1",
		IncludePayload: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.TotalCount != 1 || len(resp.Nodes) != 1 {
		t.Fatalf("unexpected response: %#v", resp)
	}
	view := resp.Nodes[0]
	if view.NodeHash != "node-1" || view.Kind != string(proofgraph.NodeTypeIntent) || view.Principal != "alice" || view.Lamport != 10 {
		t.Fatalf("unexpected node view: %#v", view)
	}
	if string(view.Payload) != `{"ok":true}` {
		t.Fatalf("payload = %s", view.Payload)
	}
}

func TestExecuteSingleNodeError(t *testing.T) {
	engine := NewEngine(&fakeStore{getErr: errors.New("missing")})
	_, err := engine.Execute(context.Background(), QueryRequest{NodeHash: "missing"})
	if err == nil || !strings.Contains(err.Error(), "graphql: node missing: missing") {
		t.Fatalf("expected wrapped node error, got %v", err)
	}
}

func TestExecuteRangeFiltersAndLimit(t *testing.T) {
	from := uint64(5)
	to := uint64(20)
	store := &fakeStore{
		nodes: []*proofgraph.Node{
			testNode("node-1", proofgraph.NodeTypeIntent, "alice", 10, `{"n":1}`),
			testNode("node-2", proofgraph.NodeTypeEffect, "alice", 11, `{"n":2}`),
			testNode("node-3", proofgraph.NodeTypeIntent, "bob", 12, `{"n":3}`),
			testNode("node-4", proofgraph.NodeTypeIntent, "alice", 13, `{"n":4}`),
		},
	}
	engine := NewEngine(store)

	resp, err := engine.Execute(context.Background(), QueryRequest{
		FromLamport: &from,
		ToLamport:   &to,
		Principal:   "alice",
		Kind:        string(proofgraph.NodeTypeIntent),
		Limit:       1,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if store.from != from || store.to != to {
		t.Fatalf("range = %d..%d, want %d..%d", store.from, store.to, from, to)
	}
	if resp.TotalCount != 1 || len(resp.Nodes) != 1 || resp.Nodes[0].NodeHash != "node-1" {
		t.Fatalf("unexpected filtered response: %#v", resp)
	}
	if resp.Nodes[0].Payload != nil {
		t.Fatalf("payload should be omitted, got %s", resp.Nodes[0].Payload)
	}
}

func TestExecuteRangeDefaultsAndError(t *testing.T) {
	store := &fakeStore{
		nodes: []*proofgraph.Node{
			testNode("node-1", proofgraph.NodeTypeIntent, "alice", 1, `{"n":1}`),
			testNode("node-2", proofgraph.NodeTypeEffect, "bob", 2, `{"n":2}`),
		},
	}
	resp, err := NewEngine(store).Execute(context.Background(), QueryRequest{})
	if err != nil {
		t.Fatalf("Execute default range: %v", err)
	}
	if store.from != 0 || store.to != ^uint64(0) {
		t.Fatalf("default range = %d..%d", store.from, store.to)
	}
	if resp.TotalCount != 2 {
		t.Fatalf("expected two nodes, got %#v", resp)
	}

	_, err = NewEngine(&fakeStore{rangeErr: errors.New("range failed")}).Execute(context.Background(), QueryRequest{})
	if err == nil || !strings.Contains(err.Error(), "graphql: range query: range failed") {
		t.Fatalf("expected range error, got %v", err)
	}
}

type fakeStore struct {
	node     *proofgraph.Node
	nodes    []*proofgraph.Node
	getErr   error
	rangeErr error
	from     uint64
	to       uint64
}

func (s *fakeStore) StoreNode(context.Context, *proofgraph.Node) error {
	return nil
}

func (s *fakeStore) GetNode(context.Context, string) (*proofgraph.Node, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.node, nil
}

func (s *fakeStore) GetNodesByType(context.Context, proofgraph.NodeType, uint64, uint64) ([]*proofgraph.Node, error) {
	return nil, nil
}

func (s *fakeStore) GetChain(context.Context, string) ([]*proofgraph.Node, error) {
	return nil, nil
}

func (s *fakeStore) GetRange(_ context.Context, fromLamport, toLamport uint64) ([]*proofgraph.Node, error) {
	s.from = fromLamport
	s.to = toLamport
	if s.rangeErr != nil {
		return nil, s.rangeErr
	}
	return s.nodes, nil
}

func testNode(hash string, kind proofgraph.NodeType, principal string, lamport uint64, payload string) *proofgraph.Node {
	return &proofgraph.Node{
		NodeHash:     hash,
		Parents:      []string{"parent"},
		Kind:         kind,
		Principal:    principal,
		PrincipalSeq: 1,
		Lamport:      lamport,
		Timestamp:    123,
		Sig:          "sig",
		Payload:      json.RawMessage(payload),
	}
}
