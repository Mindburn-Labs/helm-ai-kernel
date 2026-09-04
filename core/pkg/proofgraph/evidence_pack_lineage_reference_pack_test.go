package proofgraph

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type evidencePackSuccessorVectorFile struct {
	Role      string `json:"role"`
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type evidencePackSuccessorNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type evidencePackSuccessorVectorIndex struct {
	Comment         string                                `json:"$comment"`
	SchemaVersion   string                                `json:"schema_version"`
	ContractVersion string                                `json:"contract_version"`
	Files           []evidencePackSuccessorVectorFile     `json:"files"`
	FinalNodeChain  []string                              `json:"final_node_chain"`
	CensoredChain   []string                              `json:"censored_node_chain"`
	NegativeVectors []evidencePackSuccessorNegativeVector `json:"negative_vectors"`
}

func TestEvidencePackSuccessorReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildEvidencePackSuccessorReferencePack(t)
	root := filepath.Join(evidencePackSuccessorReferenceRepoRoot(t), "reference_packs", "evidence-pack-successor-v1")
	if os.Getenv("UPDATE_EVIDENCE_PACK_SUCCESSOR_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(root, name), content, 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_EVIDENCE_PACK_SUCCESSOR_VECTORS=1 go test ./pkg/proofgraph -run TestEvidencePackSuccessorReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildEvidencePackSuccessorReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 123456000, time.UTC) }
	lineage := proofTestEvidencePackLineage()
	sealedPack := proofTestSealedEvidencePack(t, lineage)
	sealedPackHash := sealedPack.Attestation.PackHash

	finalGraph := NewGraph().WithClock(clock)
	finalRoot, err := finalGraph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "spiffe://helm/kernel", 1)
	if err != nil {
		t.Fatal(err)
	}
	finalEvaluationNode, err := finalGraph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-1", sealedPackHash, lineage, "evidence:operational-evaluation"),
		finalRoot.NodeHash, "spiffe://helm/kernel", 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	finalEvaluation, err := DecodeEvidencePackSuccessorNode(finalEvaluationNode)
	if err != nil {
		t.Fatal(err)
	}
	progressNode, err := finalGraph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementProgress, finalEvaluation.SuccessorID, finalEvaluation.SuccessorHash, lineage, "evidence:measurement-progress"),
		finalEvaluationNode.NodeHash, "spiffe://helm/kernel", 3,
	)
	if err != nil {
		t.Fatal(err)
	}
	progress, err := DecodeEvidencePackSuccessorNode(progressNode)
	if err != nil {
		t.Fatal(err)
	}
	finalNode, err := finalGraph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementFinal, progress.SuccessorID, progress.SuccessorHash, lineage, "evidence:measurement-final"),
		progressNode.NodeHash, "spiffe://helm/kernel", 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	final, err := DecodeEvidencePackSuccessorNode(finalNode)
	if err != nil {
		t.Fatal(err)
	}

	censoredGraph := NewGraph().WithClock(clock)
	censoredRoot, err := censoredGraph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "spiffe://helm/kernel", 1)
	if err != nil {
		t.Fatal(err)
	}
	censoredEvaluationNode, err := censoredGraph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-1", sealedPackHash, lineage, "evidence:operational-evaluation"),
		censoredRoot.NodeHash, "spiffe://helm/kernel", 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	censoredEvaluation, err := DecodeEvidencePackSuccessorNode(censoredEvaluationNode)
	if err != nil {
		t.Fatal(err)
	}
	censoredNode, err := censoredGraph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementCensored, censoredEvaluation.SuccessorID, censoredEvaluation.SuccessorHash, lineage, "evidence:measurement-censored"),
		censoredEvaluationNode.NodeHash, "spiffe://helm/kernel", 3,
	)
	if err != nil {
		t.Fatal(err)
	}
	censored, err := DecodeEvidencePackSuccessorNode(censoredNode)
	if err != nil {
		t.Fatal(err)
	}

	canonicalFiles := map[string][]byte{
		"lineage.c14n.json":                mustEvidencePackSuccessorCanonical(t, lineage),
		"operational_evaluation.c14n.json": mustEvidencePackSuccessorCanonical(t, finalEvaluation),
		"measurement_progress.c14n.json":   mustEvidencePackSuccessorCanonical(t, progress),
		"measurement_final.c14n.json":      mustEvidencePackSuccessorCanonical(t, final),
		"measurement_censored.c14n.json":   mustEvidencePackSuccessorCanonical(t, censored),
		"final_nodes.c14n.json":            mustEvidencePackSuccessorCanonical(t, []*Node{finalRoot, finalEvaluationNode, progressNode, finalNode}),
		"censored_nodes.c14n.json":         mustEvidencePackSuccessorCanonical(t, []*Node{censoredRoot, censoredEvaluationNode, censoredNode}),
	}
	roles := map[string]string{
		"lineage.c14n.json": "frozen_lineage", "operational_evaluation.c14n.json": "operational_evaluation",
		"measurement_progress.c14n.json": "measurement_progress", "measurement_final.c14n.json": "measurement_final",
		"measurement_censored.c14n.json": "measurement_censored", "final_nodes.c14n.json": "proofgraph_final_chain",
		"censored_nodes.c14n.json": "proofgraph_censored_chain",
	}
	orderedNames := []string{
		"lineage.c14n.json", "operational_evaluation.c14n.json", "measurement_progress.c14n.json",
		"measurement_final.c14n.json", "measurement_censored.c14n.json", "final_nodes.c14n.json", "censored_nodes.c14n.json",
	}
	index := evidencePackSuccessorVectorIndex{
		Comment:         "Immutable EvidencePack successor hashes and ProofGraph nodes; integrity only, no deployment or production-proof claim.",
		SchemaVersion:   "evidence-pack-successor-vectors.v1",
		ContractVersion: contracts.EvidencePackSuccessorContractV1,
		FinalNodeChain:  []string{finalRoot.NodeHash, finalEvaluationNode.NodeHash, progressNode.NodeHash, finalNode.NodeHash},
		CensoredChain:   []string{censoredRoot.NodeHash, censoredEvaluationNode.NodeHash, censoredNode.NodeHash},
		NegativeVectors: []evidencePackSuccessorNegativeVector{
			{ID: "unknown_extension", Mutation: "add_unknown_successor_field", ExpectedError: "contract_rejected"},
			{ID: "frozen_outcome_substitution", Mutation: "replace_outcome_contract_hash_and_reseal", ExpectedError: "lineage_conflict"},
			{ID: "conflicting_duplicate", Mutation: "replace_evidence_hash_without_changing_identity", ExpectedError: "successor_hash_mismatch"},
			{ID: "progress_relabelled_final", Mutation: "set_progress_kind_to_measurement_final_without_reseal", ExpectedError: "successor_id_mismatch"},
			{ID: "final_then_censored", Mutation: "append_censored_after_final", ExpectedError: "measurement_closed"},
			{ID: "dangling_predecessor", Mutation: "replace_proofgraph_parent_with_unknown_hash", ExpectedError: "dangling_predecessor"},
		},
	}
	for _, name := range orderedNames {
		index.Files = append(index.Files, evidencePackSuccessorVectorFile{
			Role: roles[name], Canonical: name, SHA256: evidencePackSuccessorReferenceHash(canonicalFiles[name]),
		})
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestEntries := make([]map[string]string, 0, len(orderedNames))
	for _, name := range orderedNames {
		manifestEntries = append(manifestEntries, map[string]string{
			"file": name, "sha256": strings.TrimPrefix(evidencePackSuccessorReferenceHash(canonicalFiles[name]), "sha256:"),
		})
	}
	manifestJSON, err := json.MarshalIndent(map[string]any{
		"source_repository":  "Mindburn-Labs/helm-ai-kernel",
		"source_path":        "reference_packs/evidence-pack-successor-v1",
		"pinning_authority":  "reference_packs/evidence-pack-successor-v1/vectors.json",
		"verifier":           "reference_packs/evidence-pack-successor-v1/verify_vectors.py",
		"immutable_payloads": manifestEntries,
		"purpose":            "Source-owned, byte-exact EvidencePack successor and ProofGraph lineage interoperability fixtures.",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"vectors.json":         append(indexJSON, '\n'),
		"SOURCE-MANIFEST.json": append(manifestJSON, '\n'),
	}
	for name, content := range canonicalFiles {
		files[name] = append(content, '\n')
	}
	return files
}

func mustEvidencePackSuccessorCanonical(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := canonicalize.JCS(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func evidencePackSuccessorReferenceHash(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func evidencePackSuccessorReferenceRepoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}
