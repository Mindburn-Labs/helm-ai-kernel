package proofgraph

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestNewGraph_Empty(t *testing.T) {
	g := NewGraph()
	if g.Len() != 0 {
		t.Fatalf("new graph should have 0 nodes, got %d", g.Len())
	}
}

func TestNewGraph_HeadsEmpty(t *testing.T) {
	g := NewGraph()
	if len(g.Heads()) != 0 {
		t.Fatalf("new graph should have no heads, got %v", g.Heads())
	}
}

func TestNewGraph_LamportZero(t *testing.T) {
	g := NewGraph()
	if g.LamportClock() != 0 {
		t.Fatalf("new graph lamport should be 0, got %d", g.LamportClock())
	}
}

func TestAddNode_IncrementsLen(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	if g.Len() != 1 {
		t.Fatalf("expected 1 node, got %d", g.Len())
	}
}

func TestAddNode_SetsHead(t *testing.T) {
	g := NewGraph()
	n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	heads := g.Heads()
	if len(heads) != 1 || heads[0] != n.NodeHash {
		t.Fatalf("head should be %s, got %v", n.NodeHash, heads)
	}
}

func TestAddNode_HeadUpdatesOnSecondAppend(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	n2, _ := g.Append(NodeTypeAttestation, []byte(`{}`), "p", 2)
	heads := g.Heads()
	if len(heads) != 1 || heads[0] != n2.NodeHash {
		t.Fatalf("head should be %s after second append, got %v", n2.NodeHash, heads)
	}
}

func TestAddNode_ParentLinkage(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	n2, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p", 2)
	if len(n2.Parents) != 1 || n2.Parents[0] != n1.NodeHash {
		t.Fatalf("n2 parent should be n1, got %v", n2.Parents)
	}
}

func TestLamport_Increments(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	g.Append(NodeTypeEffect, []byte(`{}`), "p", 2)
	if g.LamportClock() != 2 {
		t.Fatalf("lamport should be 2 after 2 appends, got %d", g.LamportClock())
	}
}

func TestLamport_NodeGetsCorrectValue(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	n2, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p", 2)
	if n2.Lamport != 2 {
		t.Fatalf("second node lamport should be 2, got %d", n2.Lamport)
	}
}

func TestNodeHash_Intent(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{"a":1}`), 1, "p", 0)
	if n.NodeHash == "" {
		t.Fatal("intent node hash should not be empty")
	}
	if n.ComputeNodeHash() != n.NodeHash {
		t.Fatal("recomputed hash differs from stored hash")
	}
}

func TestNodeHash_Attestation(t *testing.T) {
	n := NewNode(NodeTypeAttestation, []string{"parent"}, []byte(`{"ok":true}`), 2, "p", 1)
	if err := n.Validate(); err != nil {
		t.Fatalf("attestation node validation failed: %v", err)
	}
}

func TestNodeHash_Effect(t *testing.T) {
	n := NewNode(NodeTypeEffect, nil, []byte(`{"effect":"done"}`), 3, "p", 2)
	if n.Kind != NodeTypeEffect {
		t.Fatalf("expected EFFECT, got %s", n.Kind)
	}
}

func TestNodeHash_TrustEvent(t *testing.T) {
	n := NewNode(NodeTypeTrustEvent, nil, []byte(`{"event":"rotate"}`), 1, "p", 0)
	if err := n.Validate(); err != nil {
		t.Fatalf("trust event node validation failed: %v", err)
	}
}

func TestNodeHash_Checkpoint(t *testing.T) {
	n := NewNode(NodeTypeCheckpoint, nil, []byte(`{}`), 1, "p", 0)
	if err := n.Validate(); err != nil {
		t.Fatalf("checkpoint node validation failed: %v", err)
	}
}

func TestNodeHash_MergeDecision(t *testing.T) {
	n := NewNode(NodeTypeMergeDecision, []string{"a", "b"}, []byte(`{"merged":true}`), 5, "p", 3)
	if err := n.Validate(); err != nil {
		t.Fatalf("merge decision node validation failed: %v", err)
	}
}

func TestNodeHash_DiffersAcrossTypes(t *testing.T) {
	a := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p", 0)
	b := NewNode(NodeTypeEffect, nil, []byte(`{}`), 1, "p", 0)
	if a.NodeHash == b.NodeHash {
		t.Fatal("different node types with same payload should have different hashes")
	}
}

func TestNodeHash_DiffersForDifferentPayloads(t *testing.T) {
	a := NewNode(NodeTypeIntent, nil, []byte(`{"x":1}`), 1, "p", 0)
	b := NewNode(NodeTypeIntent, nil, []byte(`{"x":2}`), 1, "p", 0)
	if a.NodeHash == b.NodeHash {
		t.Fatal("different payloads should produce different hashes")
	}
}

func TestNodeHash_TimestampExcluded(t *testing.T) {
	n := &Node{Kind: NodeTypeIntent, Parents: nil, Payload: json.RawMessage(`{}`), Lamport: 1, Principal: "p", PrincipalSeq: 0, Timestamp: 1000}
	n.NodeHash = n.ComputeNodeHash()
	n2 := &Node{Kind: NodeTypeIntent, Parents: nil, Payload: json.RawMessage(`{}`), Lamport: 1, Principal: "p", PrincipalSeq: 0, Timestamp: 9999}
	n2.NodeHash = n2.ComputeNodeHash()
	if n.NodeHash != n2.NodeHash {
		t.Fatal("timestamp should be excluded from hash computation")
	}
}

func TestDAGValidation_ValidChain(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p", 2)
	n3, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p", 3)
	if err := g.ValidateChain(n3.NodeHash); err != nil {
		t.Fatalf("valid chain should pass: %v", err)
	}
}

func TestDAGValidation_TamperedNode(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeIntent, []byte(`{"original":true}`), "p", 1)
	n1.Payload = json.RawMessage(`{"tampered":true}`)
	n2, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p", 2)
	if err := g.ValidateChain(n2.NodeHash); err == nil {
		t.Fatal("chain with tampered node should fail validation")
	}
}

func TestDAGValidation_MissingNode(t *testing.T) {
	g := NewGraph()
	if err := g.ValidateChain("nonexistent"); err == nil {
		t.Fatal("validation of nonexistent node should fail")
	}
}

func TestGetNode_Exists(t *testing.T) {
	g := NewGraph()
	n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	got, ok := g.Get(n.NodeHash)
	if !ok || got.NodeHash != n.NodeHash {
		t.Fatal("Get should return the appended node")
	}
}

func TestGetNode_NotFound(t *testing.T) {
	g := NewGraph()
	_, ok := g.Get("does-not-exist")
	if ok {
		t.Fatal("Get should return false for nonexistent node")
	}
}

func TestAllNodes_ReturnsAll(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	g.Append(NodeTypeEffect, []byte(`{}`), "p", 2)
	g.Append(NodeTypeCheckpoint, []byte(`{}`), "p", 3)
	nodes := g.AllNodes()
	if len(nodes) != 3 {
		t.Fatalf("AllNodes should return 3, got %d", len(nodes))
	}
}

func TestWithClock_CustomClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := NewGraph().WithClock(func() time.Time { return fixed })
	n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p", 1)
	if n.Timestamp != fixed.UnixMilli() {
		t.Fatalf("timestamp should use custom clock, got %d want %d", n.Timestamp, fixed.UnixMilli())
	}
}

func TestEncodePayload_RoundTrip(t *testing.T) {
	type P struct {
		Key string `json:"key"`
	}
	data, err := EncodePayload(P{Key: "val"})
	if err != nil {
		t.Fatal(err)
	}
	var out P
	if err := json.Unmarshal(data, &out); err != nil || out.Key != "val" {
		t.Fatal("payload round-trip failed")
	}
}

func TestInMemoryStore_StoreAndGet(t *testing.T) {
	s := NewInMemoryStore()
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p", 0)
	if err := s.StoreNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNode(context.Background(), n.NodeHash)
	if err != nil || got.NodeHash != n.NodeHash {
		t.Fatal("store+get round-trip failed")
	}
}

func TestInMemoryStore_GetNodeNotFound(t *testing.T) {
	s := NewInMemoryStore()
	_, err := s.GetNode(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing node")
	}
}

func TestInMemoryStore_GetRange(t *testing.T) {
	s := NewInMemoryStore()
	n1 := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p", 0)
	n2 := NewNode(NodeTypeEffect, nil, []byte(`{}`), 5, "p", 1)
	s.StoreNode(context.Background(), n1)
	s.StoreNode(context.Background(), n2)
	nodes, _ := s.GetRange(context.Background(), 1, 3)
	if len(nodes) != 1 || nodes[0].Lamport != 1 {
		t.Fatalf("GetRange(1,3) should return 1 node, got %d", len(nodes))
	}
}

func TestResearchPromotionPayload(t *testing.T) {
	data, err := NewResearchPromotionPayload("m1", "r1", "a1")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(NodeTypeResearchPromotion, nil, data, 1, "p", 0)
	if err := n.Validate(); err != nil {
		t.Fatalf("research promotion node should validate: %v", err)
	}
}

func TestResearchPublicationPayload(t *testing.T) {
	data, err := NewResearchPublicationPayload("m1", "pub1", "my-slug")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(NodeTypeResearchPublication, nil, data, 1, "p", 0)
	if err := n.Validate(); err != nil {
		t.Fatalf("research publication node should validate: %v", err)
	}
}
