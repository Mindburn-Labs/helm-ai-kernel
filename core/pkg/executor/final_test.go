package executor

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_MerkleProfileID(t *testing.T) {
	if MerkleProfileID != "merkle-v1" {
		t.Fatalf("want merkle-v1, got %s", MerkleProfileID)
	}
}

func TestFinal_LeafDomainSeparator(t *testing.T) {
	if len(LeafDomainSeparator) != 1 || LeafDomainSeparator[0] != 0x00 {
		t.Fatal("leaf domain separator should be 0x00")
	}
}

func TestFinal_NodeDomainSeparator(t *testing.T) {
	if len(NodeDomainSeparator) != 1 || NodeDomainSeparator[0] != 0x01 {
		t.Fatal("node domain separator should be 0x01")
	}
}

func TestFinal_MerkleBuilderNew(t *testing.T) {
	mb := NewMerkleBuilder()
	if mb == nil {
		t.Fatal("builder should not be nil")
	}
}

func TestFinal_MerkleBuilderAddLeafAndBuild(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("receipt/r1", []byte(`{"id":"r1"}`), false)
	tree, _ := mb.Build()
	if tree == nil {
		t.Fatal("tree should not be nil")
	}
	if len(tree.Root) == 0 {
		t.Fatal("root should not be empty")
	}
}

func TestFinal_MerkleTreeDeterminism(t *testing.T) {
	build := func() []byte {
		mb := NewMerkleBuilder()
		mb.AddLeafBytes("a", []byte("data-a"), false)
		mb.AddLeafBytes("b", []byte("data-b"), false)
		tr, _ := mb.Build()
		return tr.Root
	}
	r1 := build()
	r2 := build()
	if string(r1) != string(r2) {
		t.Fatal("merkle root should be deterministic")
	}
}

func TestFinal_MerkleTreeSingleLeaf(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("only", []byte("data"), false)
	tree, _ := mb.Build()
	if len(tree.Leaves) != 1 {
		t.Fatal("should have 1 leaf")
	}
}

func TestFinal_MerkleTreeMultipleLeaves(t *testing.T) {
	mb := NewMerkleBuilder()
	for i := 0; i < 8; i++ {
		mb.AddLeafBytes("leaf"+string(rune('a'+i)), []byte{byte(i)}, false)
	}
	tree, _ := mb.Build()
	if len(tree.Leaves) != 8 {
		t.Fatalf("want 8 leaves, got %d", len(tree.Leaves))
	}
}

func TestFinal_MerkleProofGenerate(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("a", []byte("data-a"), false)
	mb.AddLeafBytes("b", []byte("data-b"), false)
	tree, _ := mb.Build()
	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil {
		t.Fatal("proof should not be nil")
	}
}

func TestFinal_MerkleProofHasRoot(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("a", []byte("data-a"), false)
	mb.AddLeafBytes("b", []byte("data-b"), false)
	tree, _ := mb.Build()
	proof, _ := tree.GenerateProof(0)
	if proof.Root == "" {
		t.Fatal("proof should have root")
	}
}

func TestFinal_OutboxRecordJSON(t *testing.T) {
	r := OutboxRecord{ID: "o1", Status: "PENDING"}
	data, _ := json.Marshal(r)
	var r2 OutboxRecord
	json.Unmarshal(data, &r2)
	if r2.Status != "PENDING" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_UsageEventJSON(t *testing.T) {
	ue := UsageEvent{TenantID: "t1", EventType: "tool_call", Quantity: 100}
	data, _ := json.Marshal(ue)
	var ue2 UsageEvent
	json.Unmarshal(data, &ue2)
	if ue2.Quantity != 100 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_EvidencePackInputJSON(t *testing.T) {
	epi := EvidencePackInput{SessionID: "s1"}
	data, _ := json.Marshal(epi)
	var epi2 EvidencePackInput
	json.Unmarshal(data, &epi2)
	if epi2.SessionID != "s1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_VisualEvidenceConfigJSON(t *testing.T) {
	vec := VisualEvidenceConfig{MaxSnapshotsPerPack: 10}
	data, _ := json.Marshal(vec)
	var vec2 VisualEvidenceConfig
	json.Unmarshal(data, &vec2)
	if vec2.MaxSnapshotsPerPack != 10 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_VisualSnapshotJSON(t *testing.T) {
	vs := VisualSnapshot{SnapshotID: "s1", SequenceNum: 1}
	data, _ := json.Marshal(vs)
	var vs2 VisualSnapshot
	json.Unmarshal(data, &vs2)
	if vs2.SequenceNum != 1 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ReasoningStepJSON(t *testing.T) {
	rs := ReasoningStep{StepID: "s1", Action: "analyze"}
	data, _ := json.Marshal(rs)
	var rs2 ReasoningStep
	json.Unmarshal(data, &rs2)
	if rs2.StepID != "s1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_MerkleLeafJSON(t *testing.T) {
	ml := MerkleLeaf{Index: 0, Path: "a.json", Sealed: true}
	data, _ := json.Marshal(ml)
	var ml2 MerkleLeaf
	json.Unmarshal(data, &ml2)
	if !ml2.Sealed {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentMerkleBuild(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mb := NewMerkleBuilder()
			mb.AddLeafBytes("leaf", []byte{byte(i)}, false)
			mb.Build()
		}(i)
	}
	wg.Wait()
}

func TestFinal_MerkleProofOutOfRange(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("a", []byte("data"), false)
	tree, _ := mb.Build()
	_, err := tree.GenerateProof(99)
	if err == nil {
		t.Fatal("should error on out-of-range index")
	}
}

func TestFinal_MerkleTreeRootNonEmpty(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("x", []byte("y"), false)
	tree, _ := mb.Build()
	if len(tree.Root) == 0 {
		t.Fatal("root should not be empty")
	}
}

func TestFinal_MerkleTreeLeavesHaveHashes(t *testing.T) {
	mb := NewMerkleBuilder()
	mb.AddLeafBytes("a", []byte("data"), false)
	tree, _ := mb.Build()
	if len(tree.Leaves[0].Hash) == 0 {
		t.Fatal("leaf hash should not be empty")
	}
}

func TestFinal_MerkleTreeDifferentDataDifferentRoots(t *testing.T) {
	mb1 := NewMerkleBuilder()
	mb1.AddLeafBytes("a", []byte("data1"), false)
	mb2 := NewMerkleBuilder()
	mb2.AddLeafBytes("a", []byte("data2"), false)
	t1, _ := mb1.Build()
	t2, _ := mb2.Build()
	if string(t1.Root) == string(t2.Root) {
		t.Fatal("different data should produce different roots")
	}
}

func TestFinal_VerificationResultJSON(t *testing.T) {
	vr := VerificationResult{Verified: true}
	data, _ := json.Marshal(vr)
	var vr2 VerificationResult
	json.Unmarshal(data, &vr2)
	if !vr2.Verified {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PackExporterInterface(t *testing.T) {
	var _ PackExporter = (PackExporter)(nil)
}
