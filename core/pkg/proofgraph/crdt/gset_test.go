package crdt

import (
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

func makeNode(t *testing.T, kind proofgraph.NodeType, payload string, lamport uint64, principal string) *proofgraph.Node {
	t.Helper()
	return proofgraph.NewNode(kind, nil, []byte(payload), lamport, principal, lamport)
}

func TestGSet_Add(t *testing.T) {
	g := NewGSet()

	n1 := makeNode(t, proofgraph.NodeTypeIntent, `{"action":"create"}`, 1, "user:1")
	n2 := makeNode(t, proofgraph.NodeTypeEffect, `{"result":"ok"}`, 2, "user:1")

	if err := g.Add(n1); err != nil {
		t.Fatalf("Add n1: %v", err)
	}
	if err := g.Add(n2); err != nil {
		t.Fatalf("Add n2: %v", err)
	}

	if !g.Contains(n1.NodeHash) {
		t.Error("should contain n1")
	}
	if !g.Contains(n2.NodeHash) {
		t.Error("should contain n2")
	}
	if g.Contains("nonexistent") {
		t.Error("should not contain nonexistent hash")
	}
	if g.Len() != 2 {
		t.Errorf("Len = %d, want 2", g.Len())
	}

	got, ok := g.Get(n1.NodeHash)
	if !ok {
		t.Fatal("Get n1 failed")
	}
	if got.NodeHash != n1.NodeHash {
		t.Errorf("Get returned wrong node: %s != %s", got.NodeHash, n1.NodeHash)
	}
}

func TestGSet_Idempotent(t *testing.T) {
	g := NewGSet()

	n := makeNode(t, proofgraph.NodeTypeIntent, `{"x":1}`, 1, "p")

	if err := g.Add(n); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := g.Add(n); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if err := g.Add(n); err != nil {
		t.Fatalf("third Add: %v", err)
	}

	if g.Len() != 1 {
		t.Errorf("Len = %d, want 1 (idempotent)", g.Len())
	}
}

func TestGSet_Merge(t *testing.T) {
	a := NewGSet()
	b := NewGSet()

	n1 := makeNode(t, proofgraph.NodeTypeIntent, `{"a":1}`, 1, "p")
	n2 := makeNode(t, proofgraph.NodeTypeEffect, `{"b":2}`, 2, "p")
	n3 := makeNode(t, proofgraph.NodeTypeAttestation, `{"c":3}`, 3, "p")
	// Shared node in both sets.
	shared := makeNode(t, proofgraph.NodeTypeCheckpoint, `{"shared":true}`, 4, "p")

	if err := a.Add(n1); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(shared); err != nil {
		t.Fatal(err)
	}

	if err := b.Add(n2); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(n3); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(shared); err != nil {
		t.Fatal(err)
	}

	added := a.Merge(b)

	// Should have added n2 and n3 (shared was already in a).
	if len(added) != 2 {
		t.Errorf("Merge added %d nodes, want 2", len(added))
	}

	// a should now contain all 4.
	if a.Len() != 4 {
		t.Errorf("a.Len = %d, want 4", a.Len())
	}
	for _, n := range []*proofgraph.Node{n1, n2, n3, shared} {
		if !a.Contains(n.NodeHash) {
			t.Errorf("a missing node %s", n.NodeHash[:8])
		}
	}
}

func TestGSet_Delta(t *testing.T) {
	g := NewGSet()

	n1 := makeNode(t, proofgraph.NodeTypeIntent, `{"d":1}`, 1, "p")
	n2 := makeNode(t, proofgraph.NodeTypeEffect, `{"d":2}`, 2, "p")
	n3 := makeNode(t, proofgraph.NodeTypeAttestation, `{"d":3}`, 3, "p")

	for _, n := range []*proofgraph.Node{n1, n2, n3} {
		if err := g.Add(n); err != nil {
			t.Fatal(err)
		}
	}

	// Peer has only n1.
	peerHashes := map[string]bool{n1.NodeHash: true}
	delta := g.Delta(peerHashes)

	if len(delta) != 2 {
		t.Fatalf("Delta = %d nodes, want 2", len(delta))
	}

	deltaHashes := make(map[string]bool)
	for _, n := range delta {
		deltaHashes[n.NodeHash] = true
	}
	if !deltaHashes[n2.NodeHash] {
		t.Error("delta missing n2")
	}
	if !deltaHashes[n3.NodeHash] {
		t.Error("delta missing n3")
	}
	if deltaHashes[n1.NodeHash] {
		t.Error("delta should not include n1 (peer already has it)")
	}
}

func TestGSet_ConcurrentAdd(t *testing.T) {
	g := NewGSet()

	const goroutines = 100
	nodes := make([]*proofgraph.Node, goroutines)
	for i := range goroutines {
		nodes[i] = makeNode(t, proofgraph.NodeTypeEffect, `{"i":`+itoa(i)+`}`, uint64(i+1), "p")
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n *proofgraph.Node) {
			defer wg.Done()
			if err := g.Add(n); err != nil {
				t.Errorf("concurrent Add: %v", err)
			}
		}(nodes[i])
	}
	wg.Wait()

	if g.Len() != goroutines {
		t.Errorf("Len = %d, want %d", g.Len(), goroutines)
	}

	for _, n := range nodes {
		if !g.Contains(n.NodeHash) {
			t.Errorf("missing node after concurrent add: %s", n.NodeHash[:8])
		}
	}
}

func TestGSet_ContentAddressed(t *testing.T) {
	g := NewGSet()

	n := makeNode(t, proofgraph.NodeTypeIntent, `{"valid":true}`, 1, "p")
	// Tamper with the hash.
	n.NodeHash = "0000000000000000000000000000000000000000000000000000000000000000"

	err := g.Add(n)
	if err == nil {
		t.Fatal("expected error for node with wrong hash, got nil")
	}

	if g.Len() != 0 {
		t.Error("tampered node should not have been added")
	}
}

func TestGSet_All(t *testing.T) {
	g := NewGSet()

	n1 := makeNode(t, proofgraph.NodeTypeIntent, `{"a":1}`, 1, "p")
	n2 := makeNode(t, proofgraph.NodeTypeEffect, `{"b":2}`, 2, "p")

	if err := g.Add(n1); err != nil {
		t.Fatal(err)
	}
	if err := g.Add(n2); err != nil {
		t.Fatal(err)
	}

	all := g.All()
	if len(all) != 2 {
		t.Errorf("All returned %d nodes, want 2", len(all))
	}
}

func TestGSet_Hashes(t *testing.T) {
	g := NewGSet()

	n1 := makeNode(t, proofgraph.NodeTypeIntent, `{"h":1}`, 1, "p")
	n2 := makeNode(t, proofgraph.NodeTypeEffect, `{"h":2}`, 2, "p")

	if err := g.Add(n1); err != nil {
		t.Fatal(err)
	}
	if err := g.Add(n2); err != nil {
		t.Fatal(err)
	}

	hashes := g.Hashes()
	if len(hashes) != 2 {
		t.Errorf("Hashes returned %d entries, want 2", len(hashes))
	}
	if !hashes[n1.NodeHash] {
		t.Error("Hashes missing n1")
	}
	if !hashes[n2.NodeHash] {
		t.Error("Hashes missing n2")
	}
}

// itoa is a simple int-to-string for generating unique payloads.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
