package executor

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────
// Merkle tree with 100 leaves
// ────────────────────────────────────────────────────────────────────────

func TestStress_MerkleTree100Leaves(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 100; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/data/%d", i), map[string]int{"value": i}, false)
	}
	tree, err := mb.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Root) == 0 {
		t.Fatal("root hash is empty")
	}
	if len(tree.Leaves) != 100 {
		t.Fatalf("expected 100 leaves, got %d", len(tree.Leaves))
	}
}

func TestStress_MerkleTree100ProofVerification(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 100; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/item/%d", i), map[string]string{"k": fmt.Sprintf("v%d", i)}, false)
	}
	tree, _ := mb.Build()
	for i := 0; i < 100; i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("proof generation for leaf %d: %v", i, err)
		}
		valid, err := VerifyProof(proof)
		if err != nil || !valid {
			t.Fatalf("proof invalid for leaf %d: valid=%v err=%v", i, valid, err)
		}
	}
}

func TestStress_MerkleTreeSingleLeaf(t *testing.T) {
	mb := NewMerkleBuilder()
	_ = mb.AddLeaf("/only", "single", false)
	tree, err := mb.Build()
	if err != nil || tree.RootHex() == "" {
		t.Fatal("single leaf tree failed")
	}
}

func TestStress_MerkleTreeOddLeaves(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 7; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/odd/%d", i), i, false)
	}
	tree, err := mb.Build()
	if err != nil || tree.RootHex() == "" {
		t.Fatal("odd leaf tree failed")
	}
}

func TestStress_MerkleTreeEmpty(t *testing.T) {
	mb := NewMerkleBuilder()
	_, err := mb.Build()
	if err == nil {
		t.Fatal("expected error for empty tree")
	}
}

func TestStress_MerkleProofOutOfRange(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/x", []byte("x"), false)
	tree, _ := mb.Build()
	_, err := tree.GenerateProof(5)
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestStress_MerkleProofNegativeIndex(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/x", []byte("x"), false)
	tree, _ := mb.Build()
	_, err := tree.GenerateProof(-1)
	if err == nil {
		t.Fatal("expected negative index error")
	}
}

func TestStress_MerkleRootHex(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/a", []byte("a"), false)
	tree, _ := mb.Build()
	h := tree.RootHex()
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
}

func TestStress_MerkleDeriveView(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 10; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/path/%d", i), i, false)
	}
	tree, _ := mb.Build()
	view, err := tree.DeriveView("v1", "pack-1", []string{"/path/0", "/path/5"}, func(p string) (any, error) {
		return p, nil
	})
	if err != nil || len(view.Proofs) != 2 {
		t.Fatalf("view derivation failed: err=%v proofs=%d", err, len(view.Proofs))
	}
}

func TestStress_MerkleVerifyView(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 5; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/v/%d", i), i, false)
	}
	tree, _ := mb.Build()
	view, _ := tree.DeriveView("v1", "p1", []string{"/v/2"}, nil)
	valid, err := VerifyView(view)
	if err != nil || !valid {
		t.Fatal("view verification failed")
	}
}

func TestStress_MerkleDeriveViewMissingPath(t *testing.T) {
	mb := NewMerkleBuilder()
	_ = mb.AddLeaf("/a", "a", false)
	tree, _ := mb.Build()
	_, err := tree.DeriveView("v", "p", []string{"/missing"}, nil)
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestStress_MerkleLeafBytes(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/bin", []byte{0xDE, 0xAD}, true)
	tree, _ := mb.Build()
	if !tree.Leaves[0].Sealed {
		t.Fatal("expected sealed leaf")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Evidence pack with 50 entries
// ────────────────────────────────────────────────────────────────────────

func TestStress_ConcurrentMerkleBuilds(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mb := NewMerkleBuilder()
			for j := 0; j < 10; j++ {
				_ = mb.AddLeaf(fmt.Sprintf("/%d/%d", n, j), j, false)
			}
			tree, err := mb.Build()
			if err != nil || tree.RootHex() == "" {
				t.Errorf("goroutine %d: build failed", n)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_MCPDriverNilClient(t *testing.T) {
	d := NewMCPDriver(nil)
	_, err := d.Execute(context.Background(), "tool", nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestStress_VerifyProofInvalidLeafHash(t *testing.T) {
	proof := &MerkleProof{LeafHash: "zzzz", Root: "aaaa", Siblings: nil}
	_, err := VerifyProof(proof)
	if err == nil {
		t.Fatal("expected error for invalid leaf hash hex")
	}
}

func TestStress_VerifyProofInvalidRootHash(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/a", []byte("a"), false)
	tree, _ := mb.Build()
	proof, _ := tree.GenerateProof(0)
	proof.Root = "not-hex!"
	_, err := VerifyProof(proof)
	if err == nil {
		t.Fatal("expected error for invalid root hash hex")
	}
}

func TestStress_VerifyProofInvalidSiblingHash(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/a", []byte("a"), false)
	mb.AddLeafBytes("/b", []byte("b"), false)
	tree, _ := mb.Build()
	proof, _ := tree.GenerateProof(0)
	proof.Siblings[0].Hash = "not-hex!"
	_, err := VerifyProof(proof)
	if err == nil {
		t.Fatal("expected error for invalid sibling hash hex")
	}
}

func TestStress_VerifyProofTamperedRoot(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/a", []byte("a"), false)
	mb.AddLeafBytes("/b", []byte("b"), false)
	tree, _ := mb.Build()
	proof, _ := tree.GenerateProof(0)
	proof.Root = hex.EncodeToString(make([]byte, 32))
	valid, _ := VerifyProof(proof)
	if valid {
		t.Fatal("expected invalid proof after tampering root")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Receipt chain 50 deep
// ────────────────────────────────────────────────────────────────────────

func TestStress_MerkleChain50Deep(t *testing.T) {
	var prevRoot string
	for chain := 0; chain < 50; chain++ {
		mb := NewMerkleBuilder()
		if prevRoot != "" {
			mb.AddLeafBytes("/prev_root", []byte(prevRoot), false)
		}
		_ = mb.AddLeaf(fmt.Sprintf("/receipt/%d", chain), map[string]int{"seq": chain}, false)
		tree, err := mb.Build()
		if err != nil {
			t.Fatalf("chain %d: %v", chain, err)
		}
		prevRoot = tree.RootHex()
	}
	if prevRoot == "" {
		t.Fatal("chain should have a final root")
	}
}

func TestStress_MerkleProfileIDConstant(t *testing.T) {
	if MerkleProfileID != "merkle-v1" {
		t.Fatalf("unexpected profile ID: %s", MerkleProfileID)
	}
}

func TestStress_LeafDomainSeparator(t *testing.T) {
	if len(LeafDomainSeparator) != 1 || LeafDomainSeparator[0] != 0x00 {
		t.Fatal("unexpected leaf domain separator")
	}
}

func TestStress_NodeDomainSeparator(t *testing.T) {
	if len(NodeDomainSeparator) != 1 || NodeDomainSeparator[0] != 0x01 {
		t.Fatal("unexpected node domain separator")
	}
}

func TestStress_MerkleTreeDeterministic(t *testing.T) {
	build := func() string {
		mb := NewMerkleBuilder()
		for i := 0; i < 10; i++ {
			_ = mb.AddLeaf(fmt.Sprintf("/k/%d", i), i, false)
		}
		tree, _ := mb.Build()
		return tree.RootHex()
	}
	if build() != build() {
		t.Fatal("merkle tree not deterministic")
	}
}

func TestStress_MerkleAddLeafBytesSealed(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/sealed", []byte("secret"), true)
	tree, _ := mb.Build()
	if !tree.Leaves[0].Sealed {
		t.Fatal("expected sealed leaf")
	}
}

func TestStress_MerkleProofRootMatchesTree(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 5; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/p/%d", i), i, false)
	}
	tree, _ := mb.Build()
	proof, _ := tree.GenerateProof(2)
	if proof.Root != tree.RootHex() {
		t.Fatal("proof root does not match tree root")
	}
}

func TestStress_MerkleSealedLeafField(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("/s", []byte("data"), false)
	tree, _ := mb.Build()
	if tree.Leaves[0].Sealed {
		t.Fatal("expected unsealed leaf")
	}
}

func TestStress_MerkleTreeLevelsCount(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 8; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/l/%d", i), i, false)
	}
	tree, _ := mb.Build()
	if len(tree.Levels) < 2 {
		t.Fatal("expected at least 2 levels for 8 leaves")
	}
}

func TestStress_MCPDriverExecute(t *testing.T) {
	mock := &mockMCPClient{result: "ok"}
	d := NewMCPDriver(mock)
	result, err := d.Execute(context.Background(), "tool", nil)
	if err != nil || result != "ok" {
		t.Fatalf("expected ok, got %v err=%v", result, err)
	}
}

type mockMCPClient struct{ result any }

func (m *mockMCPClient) Call(_ string, _ map[string]any) (any, error) { return m.result, nil }

func TestStress_VerifyViewTamperedRoot(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 3; i++ {
		_ = mb.AddLeaf(fmt.Sprintf("/t/%d", i), i, false)
	}
	tree, _ := mb.Build()
	view, _ := tree.DeriveView("v", "p", []string{"/t/0"}, nil)
	view.RootHash = hex.EncodeToString(make([]byte, 32))
	valid, _ := VerifyView(view)
	if valid {
		t.Fatal("expected invalid for tampered view root")
	}
}
