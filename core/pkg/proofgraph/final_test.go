package proofgraph

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_NodeTypeConstants(t *testing.T) {
	types := []NodeType{NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect, NodeTypeTrustEvent, NodeTypeCheckpoint, NodeTypeMergeDecision, NodeTypeTrustScore, NodeTypeAgentKill, NodeTypeAgentRevive, NodeTypeSagaStart, NodeTypeSagaCompensate, NodeTypeVouch, NodeTypeSlash, NodeTypeFederation, NodeTypeHWAttestation, NodeTypeZKProof, NodeTypeDecentralizedProof}
	seen := make(map[NodeType]bool)
	for _, nt := range types {
		if nt == "" {
			t.Fatal("node type must not be empty")
		}
		if seen[nt] {
			t.Fatalf("duplicate: %s", nt)
		}
		seen[nt] = true
	}
}

func TestFinal_NodeTypeCount(t *testing.T) {
	count := 17
	types := []NodeType{NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect, NodeTypeTrustEvent, NodeTypeCheckpoint, NodeTypeMergeDecision, NodeTypeTrustScore, NodeTypeAgentKill, NodeTypeAgentRevive, NodeTypeSagaStart, NodeTypeSagaCompensate, NodeTypeVouch, NodeTypeSlash, NodeTypeFederation, NodeTypeHWAttestation, NodeTypeZKProof, NodeTypeDecentralizedProof}
	if len(types) != count {
		t.Fatalf("want %d node types, got %d", count, len(types))
	}
}

func TestFinal_NewNodeBasic(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{"action":"test"}`), 1, "p1", 0)
	if n.Kind != NodeTypeIntent {
		t.Fatal("kind mismatch")
	}
	if n.NodeHash == "" {
		t.Fatal("hash should be computed")
	}
}

func TestFinal_NodeHashDeterminism(t *testing.T) {
	n1 := NewNode(NodeTypeEffect, []string{"parent1"}, []byte(`{"key":"val"}`), 5, "p1", 1)
	n2 := NewNode(NodeTypeEffect, []string{"parent1"}, []byte(`{"key":"val"}`), 5, "p1", 1)
	if n1.NodeHash != n2.NodeHash {
		t.Fatal("same inputs should produce same hash")
	}
}

func TestFinal_NodeValidateSuccess(t *testing.T) {
	n := NewNode(NodeTypeAttestation, nil, []byte(`{}`), 1, "p1", 0)
	if err := n.Validate(); err != nil {
		t.Fatalf("valid node should pass: %v", err)
	}
}

func TestFinal_NodeValidateFailure(t *testing.T) {
	n := NewNode(NodeTypeAttestation, nil, []byte(`{}`), 1, "p1", 0)
	n.NodeHash = "tampered"
	if err := n.Validate(); err == nil {
		t.Fatal("tampered node should fail validation")
	}
}

func TestFinal_NodeJSON(t *testing.T) {
	n := NewNode(NodeTypeCheckpoint, nil, []byte(`{"seq":1}`), 10, "p1", 0)
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var n2 Node
	json.Unmarshal(data, &n2)
	if n2.Kind != NodeTypeCheckpoint {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_MaxPayloadSize(t *testing.T) {
	if MaxPayloadSize != 1<<20 {
		t.Fatal("MaxPayloadSize should be 1 MiB")
	}
}

func TestFinal_EncodePayload(t *testing.T) {
	data, err := EncodePayload(map[string]string{"key": "val"})
	if err != nil || len(data) == 0 {
		t.Fatal("EncodePayload should produce valid JSON")
	}
}

func TestFinal_InMemoryStoreInterface(t *testing.T) {
	var _ Store = (*InMemoryStore)(nil)
}

func TestFinal_InMemoryStoreAddGet(t *testing.T) {
	store := NewInMemoryStore()
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 0)
	if err := store.StoreNode(nil, n); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetNode(nil, n.NodeHash)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != NodeTypeIntent {
		t.Fatal("retrieved node mismatch")
	}
}

func TestFinal_InMemoryStoreGetMissing(t *testing.T) {
	store := NewInMemoryStore()
	_, err := store.GetNode(nil, "nonexistent")
	if err == nil {
		t.Fatal("should error on missing node")
	}
}

func TestFinal_GraphAppendAndRoots(t *testing.T) {
	g := NewGraph()
	_, err := g.Append(NodeTypeIntent, []byte(`{}`), "p1", 0)
	if err != nil {
		t.Fatal(err)
	}
	nodes := g.AllNodes()
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
}

func TestFinal_GraphNodeCount(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 0)
	g.Append(NodeTypeEffect, []byte(`{}`), "p1", 1)
	if g.Len() != 2 {
		t.Fatal("should have 2 nodes")
	}
}

func TestFinal_ConcurrentStoreAccess(t *testing.T) {
	store := NewInMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n := NewNode(NodeTypeEffect, nil, []byte(`{}`), uint64(i), "p1", uint64(i))
			store.StoreNode(nil, n)
		}(i)
	}
	wg.Wait()
}

func TestFinal_ResearchPromotionPayloadJSON(t *testing.T) {
	rp := ResearchPromotionPayload{MissionID: "m1", ReceiptHash: "abc"}
	data, _ := json.Marshal(rp)
	var rp2 ResearchPromotionPayload
	json.Unmarshal(data, &rp2)
	if rp2.MissionID != "m1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ResearchPublicationPayloadJSON(t *testing.T) {
	rpp := ResearchPublicationPayload{MissionID: "m1", Slug: "test-paper"}
	data, _ := json.Marshal(rpp)
	var rpp2 ResearchPublicationPayload
	json.Unmarshal(data, &rpp2)
	if rpp2.MissionID != "m1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_NodeComputeHashE(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 0)
	hash, err := n.ComputeNodeHashE()
	if err != nil || hash == "" {
		t.Fatal("ComputeNodeHashE should succeed")
	}
}

func TestFinal_EmptyPayloadNode(t *testing.T) {
	n := NewNode(NodeTypeTrustEvent, nil, nil, 1, "p1", 0)
	if n.NodeHash == "" {
		t.Fatal("nil-payload node should still have hash")
	}
}

func TestFinal_NodeWithParents(t *testing.T) {
	n := NewNode(NodeTypeEffect, []string{"h1", "h2"}, []byte(`{}`), 5, "p1", 3)
	if len(n.Parents) != 2 {
		t.Fatal("should have 2 parents")
	}
}

func TestFinal_GraphNewEmpty(t *testing.T) {
	g := NewGraph()
	if g.Len() != 0 {
		t.Fatal("new graph should have 0 nodes")
	}
	if len(g.AllNodes()) != 0 {
		t.Fatal("new graph should have 0 nodes")
	}
}
