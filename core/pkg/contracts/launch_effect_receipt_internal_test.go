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
