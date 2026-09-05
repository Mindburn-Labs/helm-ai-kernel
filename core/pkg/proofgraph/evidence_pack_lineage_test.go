package proofgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestEvidencePackSuccessorProofGraphLineageIsImmutableAndIdempotent(t *testing.T) {
	graph := NewGraph().WithClock(func() time.Time {
		return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	})
	lineage := proofTestEvidencePackLineage()
	sealedPack := proofTestSealedEvidencePack(t, lineage)
	root, err := graph.AppendEvidencePackRoot(
		"evidence-pack:effect-1",
		sealedPack,
		"spiffe://helm/kernel",
		1,
	)
	if err != nil {
		t.Fatalf("AppendEvidencePackRoot(): %v", err)
	}
	duplicateRoot, err := graph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "spiffe://helm/kernel", 99)
	if err != nil {
		t.Fatalf("duplicate root: %v", err)
	}
	if duplicateRoot.NodeHash != root.NodeHash || graph.Len() != 1 {
		t.Fatalf("duplicate root created a new node: got %s/%d want %s/1", duplicateRoot.NodeHash, graph.Len(), root.NodeHash)
	}

	evaluation := proofTestSuccessor(
		contracts.EvidencePackSuccessorOperationalEvaluation,
		"evidence-pack:effect-1",
		sealedPack.Attestation.PackHash,
		lineage,
		"evidence:operational-evaluation",
	)
	evaluationNode, err := graph.AppendEvidencePackSuccessor(evaluation, root.NodeHash, "spiffe://helm/kernel", 2)
	if err != nil {
		t.Fatalf("append evaluation: %v", err)
	}
	storedEvaluation, err := DecodeEvidencePackSuccessorNode(evaluationNode)
	if err != nil {
		t.Fatalf("decode evaluation node: %v", err)
	}

	progress := proofTestSuccessor(
		contracts.EvidencePackSuccessorMeasurementProgress,
		storedEvaluation.SuccessorID,
		storedEvaluation.SuccessorHash,
		lineage,
		"evidence:measurement-progress",
	)
	progressNode, err := graph.AppendEvidencePackSuccessor(progress, evaluationNode.NodeHash, "spiffe://helm/kernel", 3)
	if err != nil {
		t.Fatalf("append progress: %v", err)
	}
	storedProgress, err := DecodeEvidencePackSuccessorNode(progressNode)
	if err != nil {
		t.Fatalf("decode progress node: %v", err)
	}
	if storedProgress.FinalizesMeasurement() {
		t.Fatal("progress evidence finalized the measurement")
	}

	final := proofTestSuccessor(
		contracts.EvidencePackSuccessorMeasurementFinal,
		storedProgress.SuccessorID,
		storedProgress.SuccessorHash,
		lineage,
		"evidence:measurement-final",
	)
	finalNode, err := graph.AppendEvidencePackSuccessor(final, progressNode.NodeHash, "spiffe://helm/kernel", 4)
	if err != nil {
		t.Fatalf("append final: %v", err)
	}
	beforeDuplicate := graph.Len()
	duplicateNode, err := graph.AppendEvidencePackSuccessor(final, progressNode.NodeHash, "spiffe://helm/kernel", 99)
	if err != nil {
		t.Fatalf("duplicate append: %v", err)
	}
	if duplicateNode.NodeHash != finalNode.NodeHash || graph.Len() != beforeDuplicate {
		t.Fatalf("duplicate append created a new record: got %s/%d want %s/%d", duplicateNode.NodeHash, graph.Len(), finalNode.NodeHash, beforeDuplicate)
	}
	if err := graph.ValidateChain(finalNode.NodeHash); err != nil {
		t.Fatalf("ValidateChain(): %v", err)
	}
	if len(finalNode.Parents) != 1 || finalNode.Parents[0] != progressNode.NodeHash {
		t.Fatalf("final parents = %v want [%s]", finalNode.Parents, progressNode.NodeHash)
	}
}

func TestEvidencePackSuccessorProofGraphRejectsStalePredecessorBranches(t *testing.T) {
	for _, kind := range []contracts.EvidencePackSuccessorKind{
		contracts.EvidencePackSuccessorMeasurementProgress,
		contracts.EvidencePackSuccessorMeasurementFinal,
		contracts.EvidencePackSuccessorMeasurementCensored,
	} {
		t.Run(string(kind), func(t *testing.T) {
			lineage := proofTestEvidencePackLineage()
			sealedPack := proofTestSealedEvidencePack(t, lineage)
			graph := NewGraph()
			root, err := graph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "kernel", 1)
			if err != nil {
				t.Fatal(err)
			}
			evaluationNode, err := graph.AppendEvidencePackSuccessor(
				proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-1", sealedPack.Attestation.PackHash, lineage, "evidence:evaluation"),
				root.NodeHash,
				"kernel",
				2,
			)
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := DecodeEvidencePackSuccessorNode(evaluationNode)
			if err != nil {
				t.Fatal(err)
			}
			progressNode, err := graph.AppendEvidencePackSuccessor(
				proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementProgress, evaluation.SuccessorID, evaluation.SuccessorHash, lineage, "evidence:progress"),
				evaluationNode.NodeHash,
				"kernel",
				3,
			)
			if err != nil {
				t.Fatal(err)
			}

			stale := proofTestSuccessor(kind, evaluation.SuccessorID, evaluation.SuccessorHash, lineage, "evidence:stale-"+string(kind))
			if _, err := graph.AppendEvidencePackSuccessor(stale, evaluationNode.NodeHash, "kernel", 4); !errors.Is(err, ErrEvidencePackLineageConflict) {
				t.Fatalf("stale %s error = %v", kind, err)
			}
			if graph.Len() != 3 {
				t.Fatalf("stale %s mutated graph length: got %d want 3", kind, graph.Len())
			}
			heads := graph.Heads()
			if len(heads) != 1 || heads[0] != progressNode.NodeHash {
				t.Fatalf("stale %s mutated graph heads: got %v want [%s]", kind, heads, progressNode.NodeHash)
			}
		})
	}
}

func TestEvidencePackSuccessorProofGraphIgnoresIndependentLineageHeads(t *testing.T) {
	graph := NewGraph()
	lineageA := proofTestEvidencePackLineage()
	sealedPackA := proofTestSealedEvidencePack(t, lineageA)
	rootA, err := graph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPackA, "kernel", 1)
	if err != nil {
		t.Fatal(err)
	}
	evaluationNodeA, err := graph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-1", sealedPackA.Attestation.PackHash, lineageA, "evidence:evaluation-a"),
		rootA.NodeHash,
		"kernel",
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluationA, err := DecodeEvidencePackSuccessorNode(evaluationNodeA)
	if err != nil {
		t.Fatal(err)
	}

	lineageB := lineageA
	lineageB.TenantID = "tenant-b"
	lineageB.CompanyID = "tenant-b"
	lineageB.WorkspaceID = "workspace-b"
	lineageB.EnvironmentID = "staging-b"
	lineageB.ActivationRecordRef = "activation:company-b"
	lineageB.ActivationRecordHash = proofTestSHA("activation-record-b")
	lineageB.OutcomeContractRef = "outcome-contract:crm-hygiene-b"
	lineageB.OutcomeContractHash = proofTestSHA("outcome-contract-b")
	lineageB.MeasurementPlanRef = "measurement-plan:crm-hygiene-b"
	lineageB.MeasurementPlanHash = proofTestSHA("measurement-plan-b")
	lineageB.WindowIdentity = "window:crm-hygiene:2026-10"
	sealedPackB := proofTestSealedEvidencePack(t, lineageB)
	rootB, err := graph.AppendEvidencePackRoot("evidence-pack:effect-2", sealedPackB, "kernel", 3)
	if err != nil {
		t.Fatal(err)
	}
	evaluationB := proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-2", sealedPackB.Attestation.PackHash, lineageB, "evidence:evaluation-b")
	evaluationB.SealedPackRef = "evidence-pack:effect-2"
	evaluationNodeB, err := graph.AppendEvidencePackSuccessor(
		evaluationB,
		rootB.NodeHash,
		"kernel",
		4,
	)
	if err != nil {
		t.Fatal(err)
	}

	progress := proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementProgress, evaluationA.SuccessorID, evaluationA.SuccessorHash, lineageA, "evidence:progress-a")
	progressNode, err := graph.AppendEvidencePackSuccessor(progress, evaluationNodeA.NodeHash, "kernel", 5)
	if err != nil {
		t.Fatalf("independent lineage head blocked current predecessor: %v", err)
	}
	beforeDuplicate := graph.Len()
	duplicate, err := graph.AppendEvidencePackSuccessor(progress, evaluationNodeA.NodeHash, "kernel", 99)
	if err != nil {
		t.Fatalf("duplicate append with independent lineage head: %v", err)
	}
	if duplicate.NodeHash != progressNode.NodeHash || graph.Len() != beforeDuplicate {
		t.Fatalf("duplicate append created a new record: got %s/%d want %s/%d", duplicate.NodeHash, graph.Len(), progressNode.NodeHash, beforeDuplicate)
	}
	heads := graph.Heads()
	wantHeads := map[string]bool{evaluationNodeB.NodeHash: true, progressNode.NodeHash: true}
	if len(heads) != len(wantHeads) {
		t.Fatalf("independent lineage heads = %v", heads)
	}
	for _, head := range heads {
		if !wantHeads[head] {
			t.Fatalf("unexpected independent lineage head %s in %v", head, heads)
		}
	}
}

func TestEvidencePackSuccessorProofGraphRejectsEquivocationAndInvalidTransitions(t *testing.T) {
	lineage := proofTestEvidencePackLineage()
	sealedPack := proofTestSealedEvidencePack(t, lineage)
	graph := NewGraph()
	root, err := graph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "kernel", 1)
	if err != nil {
		t.Fatal(err)
	}
	evaluation := proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-1", sealedPack.Attestation.PackHash, lineage, "evidence:evaluation")
	evaluationNode, err := graph.AppendEvidencePackSuccessor(evaluation, root.NodeHash, "kernel", 2)
	if err != nil {
		t.Fatal(err)
	}
	sealedEvaluation, err := DecodeEvidencePackSuccessorNode(evaluationNode)
	if err != nil {
		t.Fatal(err)
	}

	equivocation := evaluation
	equivocation.EvidenceHash = proofTestSHA("conflicting-evaluation")
	if _, err := graph.AppendEvidencePackSuccessor(equivocation, root.NodeHash, "kernel", 3); !errors.Is(err, ErrEvidencePackLineageConflict) {
		t.Fatalf("equivocation error = %v", err)
	}

	drift := proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementProgress, sealedEvaluation.SuccessorID, sealedEvaluation.SuccessorHash, lineage, "evidence:progress")
	drift.Lineage.OutcomeContractHash = proofTestSHA("substituted-outcome")
	if _, err := graph.AppendEvidencePackSuccessor(drift, evaluationNode.NodeHash, "kernel", 3); !errors.Is(err, ErrEvidencePackLineageConflict) {
		t.Fatalf("frozen lineage drift error = %v", err)
	}

	directFinal := proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementFinal, "evidence-pack:effect-1", sealedPack.Attestation.PackHash, lineage, "evidence:final")
	if _, err := graph.AppendEvidencePackSuccessor(directFinal, root.NodeHash, "kernel", 3); !errors.Is(err, ErrEvidencePackLineageTransition) {
		t.Fatalf("direct final error = %v", err)
	}

	if _, err := graph.AppendEvidencePackSuccessor(drift, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "kernel", 3); !errors.Is(err, ErrEvidencePackLineageDangling) {
		t.Fatalf("dangling parent error = %v", err)
	}
}

func TestEvidencePackSuccessorProofGraphAllowsOnlyOneMeasurementClosure(t *testing.T) {
	lineage := proofTestEvidencePackLineage()
	sealedPack := proofTestSealedEvidencePack(t, lineage)
	graph := NewGraph()
	root, _ := graph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "kernel", 1)
	evaluationNode, err := graph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorOperationalEvaluation, "evidence-pack:effect-1", sealedPack.Attestation.PackHash, lineage, "evidence:evaluation"),
		root.NodeHash,
		"kernel",
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, _ := DecodeEvidencePackSuccessorNode(evaluationNode)
	finalNode, err := graph.AppendEvidencePackSuccessor(
		proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementFinal, evaluation.SuccessorID, evaluation.SuccessorHash, lineage, "evidence:final"),
		evaluationNode.NodeHash,
		"kernel",
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	final, _ := DecodeEvidencePackSuccessorNode(finalNode)

	censored := proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementCensored, evaluation.SuccessorID, evaluation.SuccessorHash, lineage, "evidence:censored")
	if _, err := graph.AppendEvidencePackSuccessor(censored, evaluationNode.NodeHash, "kernel", 4); !errors.Is(err, ErrEvidencePackLineageClosed) {
		t.Fatalf("second closure error = %v", err)
	}
	progressAfterFinal := proofTestSuccessor(contracts.EvidencePackSuccessorMeasurementProgress, final.SuccessorID, final.SuccessorHash, lineage, "evidence:late-progress")
	if _, err := graph.AppendEvidencePackSuccessor(progressAfterFinal, finalNode.NodeHash, "kernel", 5); !errors.Is(err, ErrEvidencePackLineageClosed) {
		t.Fatalf("progress after closure error = %v", err)
	}
}

func TestEvidencePackLineageRootRejectsUnsealedOrMutatedPack(t *testing.T) {
	lineage := proofTestEvidencePackLineage()
	mutated := proofTestSealedEvidencePack(t, lineage)
	mutated.Lineage.OutcomeContractHash = proofTestSHA("substituted-after-seal")
	if _, err := NewGraph().AppendEvidencePackRoot("evidence-pack:effect-1", mutated, "kernel", 1); !errors.Is(err, ErrEvidencePackLineageConflict) {
		t.Fatalf("mutated pack error = %v", err)
	}

	unbound := proofTestSealedEvidencePack(t, lineage)
	unbound.Lineage = nil
	if _, err := NewGraph().AppendEvidencePackRoot("evidence-pack:effect-1", unbound, "kernel", 1); !errors.Is(err, ErrEvidencePackLineageConflict) {
		t.Fatalf("unbound pack error = %v", err)
	}
}

func TestEvidencePackSuccessorRejectsMutatedProofGraphRoot(t *testing.T) {
	lineage := proofTestEvidencePackLineage()
	sealedPack := proofTestSealedEvidencePack(t, lineage)
	graph := NewGraph()
	root, err := graph.AppendEvidencePackRoot("evidence-pack:effect-1", sealedPack, "kernel", 1)
	if err != nil {
		t.Fatal(err)
	}
	rootHash := root.NodeHash
	root.Principal = "tampered-after-append"

	evaluation := proofTestSuccessor(
		contracts.EvidencePackSuccessorOperationalEvaluation,
		"evidence-pack:effect-1",
		sealedPack.Attestation.PackHash,
		lineage,
		"evidence:evaluation",
	)
	if _, err := graph.AppendEvidencePackSuccessor(evaluation, rootHash, "kernel", 2); !errors.Is(err, ErrEvidencePackLineageConflict) {
		t.Fatalf("mutated root error = %v", err)
	}
}

func TestEvidencePackLineageRootPayloadRejectsUnknownFields(t *testing.T) {
	root := EvidencePackLineageRootNode{
		SchemaVersion:  EvidencePackLineageRootNodeSchemaV1,
		SealedPackRef:  "evidence-pack:effect-1",
		SealedPackHash: proofTestSHA("sealed-effect-pack"),
		Lineage:        proofTestEvidencePackLineage(),
	}
	payload, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	var extended map[string]any
	if err := json.Unmarshal(payload, &extended); err != nil {
		t.Fatal(err)
	}
	extended["unknown_authority"] = "must-not-be-accepted"
	extendedPayload, err := json.Marshal(extended)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := decodeEvidencePackLineageRootPayload(extendedPayload); ok {
		t.Fatal("root payload accepted an unknown authority field")
	}
}

func proofTestEvidencePackLineage() contracts.EvidencePackLineage {
	return contracts.EvidencePackLineage{
		SchemaVersion:        contracts.EvidencePackLineageSchemaV1,
		TenantID:             "tenant-a",
		CompanyID:            "tenant-a",
		WorkspaceID:          "workspace-a",
		EnvironmentID:        "staging-a",
		ActivationRecordRef:  "activation:company-a",
		ActivationRecordHash: proofTestSHA("activation-record"),
		OutcomeContractRef:   "outcome-contract:crm-hygiene",
		OutcomeContractHash:  proofTestSHA("outcome-contract"),
		MeasurementPlanRef:   "measurement-plan:crm-hygiene",
		MeasurementPlanHash:  proofTestSHA("measurement-plan"),
		WindowIdentity:       "window:crm-hygiene:2026-09",
	}
}

func proofTestSuccessor(kind contracts.EvidencePackSuccessorKind, predecessorRef, predecessorHash string, lineage contracts.EvidencePackLineage, evidenceRef string) contracts.EvidencePackSuccessor {
	return contracts.EvidencePackSuccessor{
		SchemaVersion:   contracts.EvidencePackSuccessorSchemaV1,
		ContractVersion: contracts.EvidencePackSuccessorContractV1,
		Kind:            kind,
		PredecessorRef:  predecessorRef,
		PredecessorHash: predecessorHash,
		SealedPackRef:   "evidence-pack:effect-1",
		SealedPackHash:  predecessorSealedPackHash(kind, predecessorHash, lineage),
		Lineage:         lineage,
		EvidenceRef:     evidenceRef,
		EvidenceHash:    proofTestSHA(evidenceRef),
		RecordedAt:      time.Date(2026, 9, 4, 12, 0, 0, 123456000, time.UTC),
	}
}

func predecessorSealedPackHash(kind contracts.EvidencePackSuccessorKind, predecessorHash string, lineage contracts.EvidencePackLineage) string {
	if kind == contracts.EvidencePackSuccessorOperationalEvaluation {
		return predecessorHash
	}
	return proofTestSealedEvidencePackHash(lineage)
}

func proofTestSealedEvidencePack(t *testing.T, lineage contracts.EvidencePackLineage) *contracts.EvidencePack {
	t.Helper()
	pack := &contracts.EvidencePack{
		PackID: "pack-1", FormatVersion: "1.0.0",
		CreatedAt: time.Date(2026, 9, 4, 11, 59, 0, 0, time.UTC),
		Identity:  contracts.EvidencePackIdentity{ActorID: "actor-1", ActorType: "control_loop"},
		Policy:    contracts.EvidencePackPolicy{DecisionID: "decision-1", PolicyVersion: "v1", RulesFired: []string{}},
		Effect:    contracts.EvidencePackEffect{EffectID: "effect-1", EffectType: "CRM_UPDATE"},
		Execution: contracts.EvidencePackExecution{
			ExecutionID: "execution-1", Status: "success",
		},
		Lineage: &lineage,
		Attestation: contracts.EvidencePackAttestation{
			KernelVersion: "test",
		},
	}
	hash, err := contracts.ComputeEvidencePackHash(pack)
	if err != nil {
		t.Fatal(err)
	}
	pack.Attestation.PackHash = hash
	return pack
}

func proofTestSealedEvidencePackHash(lineage contracts.EvidencePackLineage) string {
	pack := &contracts.EvidencePack{
		PackID: "pack-1", FormatVersion: "1.0.0",
		CreatedAt: time.Date(2026, 9, 4, 11, 59, 0, 0, time.UTC),
		Identity:  contracts.EvidencePackIdentity{ActorID: "actor-1", ActorType: "control_loop"},
		Policy:    contracts.EvidencePackPolicy{DecisionID: "decision-1", PolicyVersion: "v1", RulesFired: []string{}},
		Effect:    contracts.EvidencePackEffect{EffectID: "effect-1", EffectType: "CRM_UPDATE"},
		Execution: contracts.EvidencePackExecution{
			ExecutionID: "execution-1", Status: "success",
		},
		Lineage: &lineage,
	}
	hash, err := contracts.ComputeEvidencePackHash(pack)
	if err != nil {
		panic(err)
	}
	return hash
}

func proofTestSHA(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
