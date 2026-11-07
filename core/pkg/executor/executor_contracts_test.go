package executor

import (
	"encoding/json"
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
