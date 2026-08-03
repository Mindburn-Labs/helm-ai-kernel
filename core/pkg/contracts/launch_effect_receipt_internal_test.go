// quantum_posture: these receipt evidence guard tests exercise classical
// SHA-256 content addressing only and make no hybrid or post-quantum
// protection claim.
package contracts

import (
	"strings"
	"testing"
)

func TestLaunchEvidenceRefDependsOnReceiptRejectsCaseVariantSchemes(t *testing.T) {
	receipt := LaunchEffectReceipt{
		ReceiptID:         strings.Repeat("a", 64),
		PreviousReceiptID: strings.Repeat("b", 64),
		ReceiptChainID:    "chain-a",
		EvidencePackRef:   "evidencepack://helm/pack-a",
		EvidencePackHash:  strings.Repeat("c", 64),
	}
	for _, ref := range []string{
		"sha256:" + receipt.ReceiptID,
		"SHA256:" + receipt.ReceiptID,
		"Sha256:" + receipt.PreviousReceiptID,
		"RECEIPT:" + receipt.ReceiptID,
		"EvidencePack://helm/pack-a",
		receipt.ReceiptID,
		strings.ToUpper(receipt.ReceiptID),
		receipt.ReceiptChainID,
		receipt.EvidencePackHash,
	} {
		if !launchEvidenceRefDependsOnReceipt(receipt, ref) {
			t.Errorf("launchEvidenceRefDependsOnReceipt() accepted receipt-derived ref %q", ref)
		}
	}
	for _, ref := range []string{
		"sha256:" + strings.Repeat("d", 64),
		"artifact://helm/unrelated",
		"oci://helm/image@sha256:" + strings.Repeat("e", 64),
	} {
		if launchEvidenceRefDependsOnReceipt(receipt, ref) {
			t.Errorf("launchEvidenceRefDependsOnReceipt() rejected innocent ref %q", ref)
		}
	}
}

func TestVerifyLaunchReceiptChainEvidenceRejectsCaseVariantReceiptRefs(t *testing.T) {
	receiptID := strings.Repeat("a", 64)
	chain := []LaunchEffectReceipt{{ReceiptID: receiptID, ReceiptRevision: 1}}
	dags := []LaunchEffectEvidenceDAG{{
		Nodes: []LaunchEffectEvidenceNode{{
			NodeHash:     strings.Repeat("f", 64),
			ArtifactRefs: []string{"SHA256:" + receiptID},
		}},
	}}
	if err := verifyLaunchReceiptChainEvidence(chain, dags); err == nil {
		t.Fatal("verifyLaunchReceiptChainEvidence() accepted SHA256:<receipt-id> evidence reference")
	}
	dags[0].Nodes[0].ArtifactRefs = []string{"sha256:" + strings.Repeat("d", 64)}
	if err := verifyLaunchReceiptChainEvidence(chain, dags); err != nil {
		t.Fatalf("verifyLaunchReceiptChainEvidence() rejected unrelated evidence: %v", err)
	}
}

func TestVerifyLaunchReceiptEvidenceDAGRejectsContentSubstitution(t *testing.T) {
	node := LaunchEffectEvidenceNode{
		ParentHashes: []string{}, ArtifactRefs: []string{"artifact:provider-request"},
		ProofSessionRef: "proof-session-1", EvidenceReservationRef: "evidence-reservation-1", Lamport: 1,
	}
	hash, err := ComputeLaunchEvidenceNodeHash(node)
	if err != nil {
		t.Fatal(err)
	}
	node.NodeHash = hash
	receipt := LaunchEffectReceipt{
		ProofGraphNode:         hash,
		ProofSessionRef:        "proof-session-1",
		EvidenceReservationRef: "evidence-reservation-1",
		Lamport:                2,
	}
	if err := verifyLaunchReceiptEvidenceDAG(receipt, LaunchEffectEvidenceDAG{Nodes: []LaunchEffectEvidenceNode{node}}); err != nil {
		t.Fatalf("verifyLaunchReceiptEvidenceDAG() rejected a content-bound node: %v", err)
	}
	// Substitute content under the claimed hash without recomputing it: an
	// attacker keeps the address the receipt commits to but swaps what the
	// evidence actually says.
	substituted := node
	substituted.ArtifactRefs = []string{"artifact:provider-reconciliation"}
	if err := verifyLaunchReceiptEvidenceDAG(receipt, LaunchEffectEvidenceDAG{Nodes: []LaunchEffectEvidenceNode{substituted}}); err == nil {
		t.Fatal("verifyLaunchReceiptEvidenceDAG() accepted an artifact ref substituted under a claimed node hash")
	} else if !strings.Contains(err.Error(), "does not commit to its content") {
		t.Fatalf("verifyLaunchReceiptEvidenceDAG() rejected substituted content with the wrong error: %v", err)
	}
	bumped := node
	bumped.Lamport = 2
	if err := verifyLaunchReceiptEvidenceDAG(receipt, LaunchEffectEvidenceDAG{Nodes: []LaunchEffectEvidenceNode{bumped}}); err == nil {
		t.Fatal("verifyLaunchReceiptEvidenceDAG() accepted a Lamport substitution under a claimed node hash")
	} else if !strings.Contains(err.Error(), "does not commit to its content") {
		t.Fatalf("verifyLaunchReceiptEvidenceDAG() rejected a Lamport substitution with the wrong error: %v", err)
	}
}
