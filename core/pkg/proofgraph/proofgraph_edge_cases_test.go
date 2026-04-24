package proofgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── Graph Append Tests ───────────────────────────────────────────

func TestDeepGraphAppendSingle(t *testing.T) {
	g := NewGraph()
	payload, _ := json.Marshal(map[string]string{"action": "test"})
	node, err := g.Append(NodeTypeIntent, payload, "agent-1", 1)
	if err != nil || node == nil {
		t.Fatal("append should succeed")
	}
	if node.Kind != NodeTypeIntent {
		t.Fatal("kind mismatch")
	}
}

func TestDeepGraph1000Nodes(t *testing.T) {
	g := NewGraph()
	for i := 0; i < 1000; i++ {
		payload, _ := json.Marshal(map[string]int{"i": i})
		_, err := g.Append(NodeTypeEffect, payload, "agent-1", uint64(i))
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}
	}
	if g.Len() != 1000 {
		t.Fatalf("expected 1000 nodes, got %d", g.Len())
	}
}

func TestDeepGraphLamportMonotonic(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"x":1}`)
	var prevLamport uint64
	for i := 0; i < 100; i++ {
		node, _ := g.Append(NodeTypeAttestation, payload, "p", uint64(i))
		if node.Lamport <= prevLamport && i > 0 {
			t.Fatal("Lamport clock should be monotonically increasing")
		}
		prevLamport = node.Lamport
	}
}

func TestDeepGraphValidateChain(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"ok":true}`)
	var lastHash string
	for i := 0; i < 10; i++ {
		node, _ := g.Append(NodeTypeEffect, payload, "p", uint64(i))
		lastHash = node.NodeHash
	}
	if err := g.ValidateChain(lastHash); err != nil {
		t.Fatalf("chain validation should succeed: %v", err)
	}
}

func TestDeepGraphValidateChainBroken(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"ok":true}`)
	for i := 0; i < 5; i++ {
		g.Append(NodeTypeEffect, payload, "p", uint64(i))
	}
	err := g.ValidateChain("nonexistent-hash")
	if err == nil {
		t.Fatal("validation should fail for nonexistent node")
	}
}

func TestDeepGraphHeadsUpdate(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"x":1}`)
	n1, _ := g.Append(NodeTypeIntent, payload, "p", 1)
	heads1 := g.Heads()
	if len(heads1) != 1 || heads1[0] != n1.NodeHash {
		t.Fatal("heads should contain latest node")
	}
	n2, _ := g.Append(NodeTypeEffect, payload, "p", 2)
	heads2 := g.Heads()
	if len(heads2) != 1 || heads2[0] != n2.NodeHash {
		t.Fatal("heads should update to latest node")
	}
}

func TestDeepGraphAllNodes(t *testing.T) {
	g := NewGraph()
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]int{"i": i})
		g.Append(NodeTypeEffect, payload, "p", uint64(i))
	}
	nodes := g.AllNodes()
	if len(nodes) != 5 {
		t.Fatalf("expected 5 nodes, got %d", len(nodes))
	}
}

func TestDeepGraphGet(t *testing.T) {
	g := NewGraph()
	n, _ := g.Append(NodeTypeIntent, []byte(`{"x":1}`), "p", 1)
	got, ok := g.Get(n.NodeHash)
	if !ok || got.NodeHash != n.NodeHash {
		t.Fatal("Get should retrieve stored node")
	}
	_, ok = g.Get("nonexistent")
	if ok {
		t.Fatal("Get should return false for missing node")
	}
}

// ── Node Hash Tests ──────────────────────────────────────────────

func TestDeepNodeHashDeterministic(t *testing.T) {
	clk := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	payload := []byte(`{"test":"value"}`)
	n1 := NewNode(NodeTypeIntent, nil, payload, 1, "agent-1", 1, clk)
	n2 := NewNode(NodeTypeIntent, nil, payload, 1, "agent-1", 1, clk)
	if n1.NodeHash != n2.NodeHash {
		t.Fatal("same inputs should produce same hash")
	}
}

func TestDeepNodeHashDiffersOnPayload(t *testing.T) {
	clk := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	n1 := NewNode(NodeTypeIntent, nil, []byte(`{"a":1}`), 1, "p", 1, clk)
	n2 := NewNode(NodeTypeIntent, nil, []byte(`{"a":2}`), 1, "p", 1, clk)
	if n1.NodeHash == n2.NodeHash {
		t.Fatal("different payloads should produce different hashes")
	}
}

func TestDeepNodeHashDiffersOnKind(t *testing.T) {
	clk := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	payload := []byte(`{"same":true}`)
	n1 := NewNode(NodeTypeIntent, nil, payload, 1, "p", 1, clk)
	n2 := NewNode(NodeTypeEffect, nil, payload, 1, "p", 1, clk)
	if n1.NodeHash == n2.NodeHash {
		t.Fatal("different kinds should produce different hashes")
	}
}

func TestDeepNodeHashDiffersOnLamport(t *testing.T) {
	clk := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	payload := []byte(`{"same":true}`)
	n1 := NewNode(NodeTypeEffect, nil, payload, 1, "p", 1, clk)
	n2 := NewNode(NodeTypeEffect, nil, payload, 2, "p", 1, clk)
	if n1.NodeHash == n2.NodeHash {
		t.Fatal("different Lamport clocks should produce different hashes")
	}
}

func TestDeepNodeValidateIntegrity(t *testing.T) {
	n := NewNode(NodeTypeEffect, nil, []byte(`{"ok":true}`), 1, "p", 1)
	if err := n.Validate(); err != nil {
		t.Fatal("valid node should pass validation")
	}
}

func TestDeepNodeValidateTampered(t *testing.T) {
	n := NewNode(NodeTypeEffect, nil, []byte(`{"ok":true}`), 1, "p", 1)
	n.Principal = "tampered"
	if err := n.Validate(); err == nil {
		t.Fatal("tampered node should fail validation")
	}
}

func TestDeepNodeHashForEveryType(t *testing.T) {
	types := []NodeType{
		NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect, NodeTypeTrustEvent,
		NodeTypeCheckpoint, NodeTypeMergeDecision, NodeTypeTrustScore, NodeTypeAgentKill,
		NodeTypeAgentRevive, NodeTypeSagaStart, NodeTypeSagaCompensate, NodeTypeVouch,
		NodeTypeSlash, NodeTypeFederation, NodeTypeHWAttestation, NodeTypeZKProof,
		NodeTypeDecentralizedProof,
	}
	hashes := map[string]bool{}
	for _, nt := range types {
		payload, _ := json.Marshal(map[string]string{"type": string(nt)})
		n := NewNode(nt, nil, payload, 1, "p", 1)
		if hashes[n.NodeHash] {
			t.Fatalf("duplicate hash for different node type %s", nt)
		}
		hashes[n.NodeHash] = true
	}
	if len(hashes) < 15 {
		t.Fatalf("expected at least 15 unique hashes, got %d", len(hashes))
	}
}

func TestDeepNodeComputeNodeHashE(t *testing.T) {
	n := NewNode(NodeTypeEffect, nil, []byte(`{"x":1}`), 1, "p", 1)
	hash, err := n.ComputeNodeHashE()
	if err != nil || hash == "" {
		t.Fatal("ComputeNodeHashE should succeed")
	}
	if hash != n.NodeHash {
		t.Fatal("ComputeNodeHashE should match stored hash")
	}
}

// ── DAG Diamond Pattern Test ─────────────────────────────────────

func TestDeepGraphDiamondPattern(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"ok":true}`)
	// A -> heads
	nodeA, _ := g.Append(NodeTypeIntent, payload, "p", 1)
	// B -> A
	nodeB, _ := g.Append(NodeTypeAttestation, payload, "p", 2)
	// Manually construct C -> A (need to modify heads to create diamond)
	g.mu.Lock()
	g.heads = []string{nodeA.NodeHash}
	g.mu.Unlock()
	nodeC, _ := g.Append(NodeTypeAttestation, payload, "p", 3)
	// D -> B, C (set heads to both B and C)
	g.mu.Lock()
	g.heads = []string{nodeB.NodeHash, nodeC.NodeHash}
	g.mu.Unlock()
	nodeD, _ := g.Append(NodeTypeEffect, payload, "p", 4)
	// D should have B and C as parents
	if len(nodeD.Parents) != 2 {
		t.Fatalf("diamond tip should have 2 parents, got %d", len(nodeD.Parents))
	}
	// All 4 nodes should exist
	if g.Len() != 4 {
		t.Fatalf("expected 4 nodes, got %d", g.Len())
	}
}

// ── AppendSigned Test ────────────────────────────────────────────

func TestDeepGraphAppendSigned(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"signed":true}`)
	node, err := g.AppendSigned(NodeTypeAttestation, payload, "sig-abc", "p", 1)
	if err != nil {
		t.Fatal(err)
	}
	if node.Sig != "sig-abc" {
		t.Fatal("signature should be preserved")
	}
	if err := node.Validate(); err != nil {
		t.Fatal("signed node should validate")
	}
}

// ── Concurrent Append Tests ──────────────────────────────────────

func TestDeepGraphConcurrentAppend(t *testing.T) {
	g := NewGraph()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]int{"idx": idx})
			g.Append(NodeTypeEffect, payload, fmt.Sprintf("p-%d", idx), uint64(idx))
		}(i)
	}
	wg.Wait()
	if g.Len() != 100 {
		t.Fatalf("expected 100 nodes after concurrent append, got %d", g.Len())
	}
}

func TestDeepGraphLamportConcurrent(t *testing.T) {
	g := NewGraph()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Append(NodeTypeCheckpoint, []byte(`{}`), "p", 1)
		}()
	}
	wg.Wait()
	if g.LamportClock() != 50 {
		t.Fatalf("expected Lamport 50, got %d", g.LamportClock())
	}
}

// ── InMemoryStore Tests ──────────────────────────────────────────

func TestDeepInMemoryStoreStoreAndGet(t *testing.T) {
	store := NewInMemoryStore()
	n := NewNode(NodeTypeIntent, nil, []byte(`{"test":1}`), 1, "p", 1)
	if err := store.StoreNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetNode(context.Background(), n.NodeHash)
	if err != nil || got.NodeHash != n.NodeHash {
		t.Fatal("stored node should be retrievable")
	}
}

func TestDeepInMemoryStoreGetNodeNotFound(t *testing.T) {
	store := NewInMemoryStore()
	_, err := store.GetNode(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("should error for missing node")
	}
}

func TestDeepInMemoryStoreGetByType(t *testing.T) {
	store := NewInMemoryStore()
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]int{"i": i})
		n := NewNode(NodeTypeEffect, nil, payload, uint64(i+1), "p", uint64(i))
		store.StoreNode(context.Background(), n)
	}
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]int{"i": i + 100})
		n := NewNode(NodeTypeCheckpoint, nil, payload, uint64(i+6), "p", uint64(i))
		store.StoreNode(context.Background(), n)
	}
	effects, _ := store.GetNodesByType(context.Background(), NodeTypeEffect, 0, 100)
	if len(effects) != 5 {
		t.Fatalf("expected 5 effects, got %d", len(effects))
	}
}

func TestDeepInMemoryStoreGetRange(t *testing.T) {
	store := NewInMemoryStore()
	for i := 0; i < 10; i++ {
		payload, _ := json.Marshal(map[string]int{"i": i})
		n := NewNode(NodeTypeEffect, nil, payload, uint64(i+1), "p", uint64(i))
		store.StoreNode(context.Background(), n)
	}
	nodes, _ := store.GetRange(context.Background(), 3, 7)
	if len(nodes) < 1 {
		t.Fatal("range query should return nodes")
	}
}

func TestDeepInMemoryStoreGetChain(t *testing.T) {
	store := NewInMemoryStore()
	g := store.Graph()
	payload := []byte(`{"x":1}`)
	var lastHash string
	for i := 0; i < 5; i++ {
		node, _ := g.Append(NodeTypeEffect, payload, "p", uint64(i))
		lastHash = node.NodeHash
	}
	chain, err := store.GetChain(context.Background(), lastHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) < 2 {
		t.Fatal("chain should contain multiple nodes")
	}
}

func TestDeepEncodePayload(t *testing.T) {
	payload, err := EncodePayload(map[string]string{"key": "value"})
	if err != nil || len(payload) == 0 {
		t.Fatal("EncodePayload should succeed")
	}
	if !json.Valid(payload) {
		t.Fatal("encoded payload should be valid JSON")
	}
}
