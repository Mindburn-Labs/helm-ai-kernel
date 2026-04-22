package crdt

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

func TestDistributedStore_Append(t *testing.T) {
	store := NewDistributedStore()
	ctx := context.Background()

	n := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"store":"test"}`), 1, "p", 1)

	if err := store.StoreNode(ctx, n); err != nil {
		t.Fatalf("StoreNode: %v", err)
	}

	// Store should have one node.
	if store.GSet().Len() != 1 {
		t.Errorf("GSet.Len = %d, want 1", store.GSet().Len())
	}

	// Idempotent.
	if err := store.StoreNode(ctx, n); err != nil {
		t.Fatalf("second StoreNode: %v", err)
	}
	if store.GSet().Len() != 1 {
		t.Errorf("GSet.Len after duplicate = %d, want 1", store.GSet().Len())
	}
}

func TestDistributedStore_Get(t *testing.T) {
	store := NewDistributedStore()
	ctx := context.Background()

	n := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"get":"test"}`), 1, "p", 1)
	if err := store.StoreNode(ctx, n); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetNode(ctx, n.NodeHash)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.NodeHash != n.NodeHash {
		t.Errorf("got hash %s, want %s", got.NodeHash, n.NodeHash)
	}

	// Not found.
	_, err = store.GetNode(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent node")
	}
}

func TestDistributedStore_List(t *testing.T) {
	store := NewDistributedStore()
	ctx := context.Background()

	n1 := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"list":1}`), 1, "p", 1)
	n2 := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"list":2}`), 2, "p", 2)
	n3 := proofgraph.NewNode(proofgraph.NodeTypeAttestation, nil, []byte(`{"list":3}`), 3, "p", 3)

	for _, n := range []*proofgraph.Node{n1, n2, n3} {
		if err := store.StoreNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	// GetRange should return all nodes in range.
	all, err := store.GetRange(ctx, 1, 3)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("GetRange returned %d nodes, want 3", len(all))
	}

	// Partial range.
	partial, err := store.GetRange(ctx, 2, 3)
	if err != nil {
		t.Fatalf("GetRange partial: %v", err)
	}
	if len(partial) != 2 {
		t.Errorf("GetRange partial returned %d nodes, want 2", len(partial))
	}
}

func TestDistributedStore_GetNodesByType(t *testing.T) {
	store := NewDistributedStore()
	ctx := context.Background()

	n1 := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"type":1}`), 1, "p", 1)
	n2 := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"type":2}`), 2, "p", 2)
	n3 := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"type":3}`), 3, "p", 3)

	for _, n := range []*proofgraph.Node{n1, n2, n3} {
		if err := store.StoreNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	intents, err := store.GetNodesByType(ctx, proofgraph.NodeTypeIntent, 1, 10)
	if err != nil {
		t.Fatalf("GetNodesByType: %v", err)
	}
	if len(intents) != 2 {
		t.Errorf("got %d intents, want 2", len(intents))
	}

	effects, err := store.GetNodesByType(ctx, proofgraph.NodeTypeEffect, 1, 10)
	if err != nil {
		t.Fatalf("GetNodesByType: %v", err)
	}
	if len(effects) != 1 {
		t.Errorf("got %d effects, want 1", len(effects))
	}
}

func TestDistributedStore_GetChain(t *testing.T) {
	store := NewDistributedStore()
	ctx := context.Background()

	n1 := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"chain":1}`), 1, "p", 1)
	n2 := proofgraph.NewNode(proofgraph.NodeTypeAttestation, []string{n1.NodeHash}, []byte(`{"chain":2}`), 2, "p", 2)
	n3 := proofgraph.NewNode(proofgraph.NodeTypeEffect, []string{n2.NodeHash}, []byte(`{"chain":3}`), 3, "p", 3)

	for _, n := range []*proofgraph.Node{n1, n2, n3} {
		if err := store.StoreNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	chain, err := store.GetChain(ctx, n3.NodeHash)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(chain) != 3 {
		t.Errorf("chain length = %d, want 3", len(chain))
	}
}

func TestDistributedStore_WithGSet(t *testing.T) {
	gset := NewGSet()
	store := NewDistributedStoreWithGSet(gset)

	ctx := context.Background()
	n := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"shared":true}`), 1, "p", 1)

	if err := store.StoreNode(ctx, n); err != nil {
		t.Fatal(err)
	}

	// Verify the underlying GSet has the node.
	if !gset.Contains(n.NodeHash) {
		t.Error("shared GSet should contain the node")
	}
	if store.GSet() != gset {
		t.Error("GSet() should return the shared instance")
	}
}
