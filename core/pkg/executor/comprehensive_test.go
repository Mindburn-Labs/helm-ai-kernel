package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// --- Merkle Tree ---

func TestMerkle_SingleLeafRootEqualsLeaf(t *testing.T) {
	b := NewMerkleBuilder()
	b.AddLeafBytes("/a", []byte("data"), false)
	tree, err := b.Build()
	if err != nil || len(tree.Root) == 0 {
		t.Fatalf("single leaf build failed: %v", err)
	}
}

func TestMerkle_TwoLeavesRootDiffers(t *testing.T) {
	b := NewMerkleBuilder()
	b.AddLeafBytes("/a", []byte("data1"), false)
	b.AddLeafBytes("/b", []byte("data2"), false)
	tree, _ := b.Build()
	if string(tree.Root) == string(tree.Leaves[0].Hash) {
		t.Fatal("root should differ from leaf hash when 2 leaves present")
	}
}

func TestMerkle_EmptyTreeErrors(t *testing.T) {
	b := NewMerkleBuilder()
	_, err := b.Build()
	if err == nil {
		t.Fatal("empty tree should error")
	}
}

func TestMerkle_DeterministicRoot(t *testing.T) {
	build := func() string {
		b := NewMerkleBuilder()
		_ = b.AddLeaf("/x", map[string]any{"k": "v"}, false)
		_ = b.AddLeaf("/y", "val", false)
		tree, _ := b.Build()
		return tree.RootHex()
	}
	if build() != build() {
		t.Fatal("deterministic builds should produce identical roots")
	}
}

func TestMerkle_ProofVerifies(t *testing.T) {
	b := NewMerkleBuilder()
	_ = b.AddLeaf("/a", "x", false)
	_ = b.AddLeaf("/b", "y", false)
	_ = b.AddLeaf("/c", "z", false)
	tree, _ := b.Build()
	proof, _ := tree.GenerateProof(1)
	valid, err := VerifyProof(proof)
	if err != nil || !valid {
		t.Fatalf("proof should verify: valid=%v err=%v", valid, err)
	}
}

func TestMerkle_TamperedProofFails(t *testing.T) {
	b := NewMerkleBuilder()
	_ = b.AddLeaf("/a", "x", false)
	_ = b.AddLeaf("/b", "y", false)
	tree, _ := b.Build()
	proof, _ := tree.GenerateProof(0)
	proof.LeafHash = strings.Repeat("0", 64)
	valid, _ := VerifyProof(proof)
	if valid {
		t.Fatal("tampered proof should fail verification")
	}
}

func TestMerkle_ProofOutOfRangeErrors(t *testing.T) {
	b := NewMerkleBuilder()
	b.AddLeafBytes("/a", []byte("x"), false)
	tree, _ := b.Build()
	_, err := tree.GenerateProof(5)
	if err == nil {
		t.Fatal("out-of-range index should error")
	}
}

func TestMerkle_DomainSeparatorsDiffer(t *testing.T) {
	if LeafDomainSeparator[0] == NodeDomainSeparator[0] {
		t.Fatal("leaf and node domain separators must differ")
	}
}

func TestMerkle_SealedLeafMarked(t *testing.T) {
	b := NewMerkleBuilder()
	b.AddLeafBytes("/secret", []byte("classified"), true)
	tree, _ := b.Build()
	if !tree.Leaves[0].Sealed {
		t.Fatal("sealed flag should be set")
	}
}

// --- EvidenceView ---

func TestEvidenceView_DeriveAndVerify(t *testing.T) {
	b := NewMerkleBuilder()
	_ = b.AddLeaf("/a", "x", false)
	_ = b.AddLeaf("/b", "y", false)
	tree, _ := b.Build()
	view, err := tree.DeriveView("v1", "p1", []string{"/a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := VerifyView(view)
	if err != nil || !valid {
		t.Fatalf("view should verify: valid=%v err=%v", valid, err)
	}
}

func TestEvidenceView_MissingPathErrors(t *testing.T) {
	b := NewMerkleBuilder()
	_ = b.AddLeaf("/a", "x", false)
	tree, _ := b.Build()
	_, err := tree.DeriveView("v1", "p1", []string{"/missing"}, nil)
	if err == nil {
		t.Fatal("missing path should error")
	}
}

// --- EvidencePack ---

func TestEvidencePack_ProduceCreatesPackID(t *testing.T) {
	p := NewEvidencePackProducer("v1.0")
	pack, err := p.Produce(context.Background(), &EvidencePackInput{
		ActorID: "agent-1", DecisionID: "d-1", EffectID: "e-1", Status: "SUCCESS",
	})
	if err != nil || pack.PackID == "" {
		t.Fatalf("pack should have ID: err=%v", err)
	}
}

func TestEvidencePack_AttestationHashSet(t *testing.T) {
	p := NewEvidencePackProducer("v1.0")
	pack, _ := p.Produce(context.Background(), &EvidencePackInput{
		ActorID: "a", DecisionID: "d", EffectID: "e", Status: "SUCCESS",
	})
	if !strings.HasPrefix(pack.Attestation.PackHash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", pack.Attestation.PackHash)
	}
}

func TestEvidencePack_DurationComputed(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(500 * time.Millisecond)
	p := NewEvidencePackProducer("v1.0")
	pack, _ := p.Produce(context.Background(), &EvidencePackInput{
		ActorID: "a", DecisionID: "d", EffectID: "e", Status: "SUCCESS",
		StartedAt: start, CompletedAt: end,
	})
	if pack.Execution.DurationMs != 500 {
		t.Fatalf("expected 500ms, got %d", pack.Execution.DurationMs)
	}
}

func TestEvidencePack_ValidateEmpty(t *testing.T) {
	issues := ValidateEvidencePack(&contracts.EvidencePack{})
	if len(issues) == 0 {
		t.Fatal("empty pack should have validation issues")
	}
}

func TestEvidencePack_ValidateComplete(t *testing.T) {
	p := NewEvidencePackProducer("v1.0")
	pack, _ := p.Produce(context.Background(), &EvidencePackInput{
		ActorID: "a", DecisionID: "d", EffectID: "e", Status: "SUCCESS",
	})
	issues := ValidateEvidencePack(pack)
	if len(issues) != 0 {
		t.Fatalf("complete pack should have no issues: %v", issues)
	}
}

// --- Receipt signing / hash ---

func TestReceiptHashDeterministic(t *testing.T) {
	data := []byte("receipt-content")
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(data)
	if hex.EncodeToString(h1[:]) != hex.EncodeToString(h2[:]) {
		t.Fatal("SHA-256 should be deterministic")
	}
}

func TestCanonicalJSON_SortedKeys(t *testing.T) {
	obj := map[string]any{"z": 1, "a": 2}
	data, err := canonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	aIdx := strings.Index(s, `"a"`)
	zIdx := strings.Index(s, `"z"`)
	if aIdx > zIdx {
		t.Fatalf("keys should be sorted: %s", s)
	}
}

// --- MCPDriver ---

func TestMCPDriver_NilClientErrors(t *testing.T) {
	d := NewMCPDriver(nil)
	_, err := d.Execute(context.Background(), "tool", nil)
	if err == nil {
		t.Fatal("nil client should error")
	}
}

func TestMerkle_RootHexFormat(t *testing.T) {
	b := NewMerkleBuilder()
	b.AddLeafBytes("/a", []byte("data"), false)
	tree, _ := b.Build()
	h := tree.RootHex()
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex root, got len=%d", len(h))
	}
}
