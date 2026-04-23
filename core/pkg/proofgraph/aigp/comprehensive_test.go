package aigp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// ── PCD ─────────────────────────────────────────────────────────

func TestComputePCDHash_Deterministic(t *testing.T) {
	pcd := &ProofCarryingDecision{
		Version:    PCDVersion,
		ID:         "pcd:abc123",
		Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Action:     GovernanceAction{Type: ActionToolExecution, Principal: "agent-1"},
		Evidence:   CryptographicEvidence{GovernanceHash: "gh1", HashAlgorithm: "SHA-256"},
		Provenance: PCDProvenance{Source: "helm", ProofGraphVersion: "v1.2"},
	}
	h1 := pcd.ComputePCDHash()
	h2 := pcd.ComputePCDHash()
	if h1 != h2 {
		t.Error("PCD hash should be deterministic")
	}
	if h1 == "" {
		t.Error("PCD hash should not be empty")
	}
}

func TestNodeTypeToAction_Intent(t *testing.T) {
	if nodeTypeToAction(proofgraph.NodeTypeIntent) != ActionPolicyEval {
		t.Error("INTENT should map to policy_evaluation")
	}
}

func TestNodeTypeToAction_Effect(t *testing.T) {
	if nodeTypeToAction(proofgraph.NodeTypeEffect) != ActionToolExecution {
		t.Error("EFFECT should map to tool_execution")
	}
}

func TestNodeTypeToAction_TrustEvent(t *testing.T) {
	if nodeTypeToAction(proofgraph.NodeTypeTrustEvent) != ActionTrustEvent {
		t.Error("TRUST_EVENT should map to trust_event")
	}
}

func TestNodeTypeToAction_Checkpoint(t *testing.T) {
	if nodeTypeToAction(proofgraph.NodeTypeCheckpoint) != ActionCheckpoint {
		t.Error("CHECKPOINT should map to checkpoint")
	}
}

// ── Exporter ────────────────────────────────────────────────────

func TestNewExporter_DefaultsApplied(t *testing.T) {
	exp := NewExporter(ExporterConfig{})
	if exp.cfg.Source != "helm" {
		t.Errorf("expected default source helm, got %s", exp.cfg.Source)
	}
	if exp.cfg.ProofGraphVersion != "v1.2" {
		t.Errorf("expected v1.2, got %s", exp.cfg.ProofGraphVersion)
	}
}

func TestExporter_ExportNode_NilNode(t *testing.T) {
	exp := NewExporter(ExporterConfig{})
	_, err := exp.ExportNode(nil)
	if err == nil {
		t.Error("should reject nil node")
	}
}

func TestExporter_ExportNode_ProducesValidPCD(t *testing.T) {
	exp := NewExporter(ExporterConfig{Source: "test-helm"})
	payload, _ := json.Marshal(map[string]string{"decision": "ALLOW", "tool": "read_file"})
	node := &proofgraph.Node{
		NodeHash:  "abc123",
		Kind:      proofgraph.NodeTypeAttestation,
		Parents:   []string{"parent1"},
		Lamport:   42,
		Principal: "agent-001",
		Payload:   payload,
		Sig:       "sig-hex",
		Timestamp: time.Now().UnixMilli(),
	}
	pcd, err := exp.ExportNode(node)
	if err != nil {
		t.Fatalf("ExportNode: %v", err)
	}
	if pcd.Version != PCDVersion {
		t.Errorf("expected version %s, got %s", PCDVersion, pcd.Version)
	}
	if pcd.Action.Decision != "ALLOW" {
		t.Errorf("expected decision ALLOW, got %s", pcd.Action.Decision)
	}
	if pcd.Action.Tool != "read_file" {
		t.Errorf("expected tool read_file, got %s", pcd.Action.Tool)
	}
	if !pcd.FourTests.Stoppable || !pcd.FourTests.Owned || !pcd.FourTests.Replayable || !pcd.FourTests.Escalatable {
		t.Error("all four tests should be true by default")
	}
	if pcd.PCDHash == "" {
		t.Error("PCDHash should be computed")
	}
}

// ── MerkleTree ──────────────────────────────────────────────────

func TestComprehensive_MerkleTree_EmptyTree(t *testing.T) {
	tree := NewMerkleTree(nil)
	if tree.Root() != "" {
		t.Error("empty tree should have empty root")
	}
}

func TestComprehensive_MerkleTree_SingleLeaf(t *testing.T) {
	tree := NewMerkleTree([]string{"leaf1"})
	if tree.Root() == "" {
		t.Error("single leaf tree should have a root")
	}
}

func TestComprehensive_MerkleTree_TwoLeaves(t *testing.T) {
	tree := NewMerkleTree([]string{"a", "b"})
	root := tree.Root()
	if root == "" {
		t.Error("root should not be empty")
	}
	expected := hashPair("a", "b")
	if root != expected {
		t.Errorf("expected %s, got %s", expected, root)
	}
}

func TestComprehensive_MerkleTree_InclusionProof_Valid(t *testing.T) {
	hashes := []string{"h1", "h2", "h3", "h4"}
	tree := NewMerkleTree(hashes)
	proof, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if !VerifyInclusion(proof) {
		t.Error("inclusion proof should verify")
	}
}

func TestComprehensive_MerkleTree_InclusionProof_OutOfRange(t *testing.T) {
	tree := NewMerkleTree([]string{"a", "b"})
	_, err := tree.InclusionProof(5)
	if err == nil {
		t.Error("should reject out-of-range index")
	}
}

func TestComprehensive_VerifyInclusion_AllLeaves(t *testing.T) {
	hashes := []string{"a", "b", "c", "d"}
	tree := NewMerkleTree(hashes)
	for i := range hashes {
		proof, _ := tree.InclusionProof(i)
		if !VerifyInclusion(proof) {
			t.Errorf("inclusion proof for leaf %d should verify", i)
		}
	}
}

func TestComprehensive_PCDVersion_Constant(t *testing.T) {
	if PCDVersion != "aigp-pcd-v1" {
		t.Errorf("expected aigp-pcd-v1, got %s", PCDVersion)
	}
}
