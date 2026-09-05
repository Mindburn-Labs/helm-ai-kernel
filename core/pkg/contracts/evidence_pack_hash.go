package contracts

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// ComputeEvidencePackHash computes the existing EvidencePack v1 attestation
// hash projection. Lineage is included when present so the activation,
// outcome, measurement, and window identity are frozen before any successor
// can be appended. The explicit projection preserves legacy hash behavior for
// packs without lineage.
func ComputeEvidencePackHash(pack *EvidencePack) (string, error) {
	if pack == nil {
		return "", fmt.Errorf("evidence pack is required")
	}
	hashable := struct {
		PackID             string                     `json:"pack_id"`
		FormatVersion      string                     `json:"format_version"`
		CreatedAt          time.Time                  `json:"created_at"`
		Identity           EvidencePackIdentity       `json:"identity"`
		Policy             EvidencePackPolicy         `json:"policy"`
		Effect             EvidencePackEffect         `json:"effect"`
		Context            EvidencePackContext        `json:"context"`
		Execution          EvidencePackExecution      `json:"execution"`
		Receipts           EvidencePackReceipts       `json:"receipts"`
		Reconciliation     EvidencePackReconciliation `json:"reconciliation"`
		ReplayScript       *ReplayScriptRef           `json:"replay_script,omitempty"`
		Provenance         *ReceiptProvenance         `json:"provenance,omitempty"`
		BundledArtifacts   []ParsedArtifact           `json:"bundled_artifacts,omitempty"`
		VerificationScopes []VerificationScope        `json:"verification_scopes,omitempty"`
		HarnessTraceRefs   []HarnessTraceRef          `json:"harness_trace_refs,omitempty"`
		EUAIActProfile     *EUAIActEvidenceProfile    `json:"eu_ai_act_profile,omitempty"`
		Lineage            *EvidencePackLineage       `json:"lineage,omitempty"`
	}{
		PackID:             pack.PackID,
		FormatVersion:      pack.FormatVersion,
		CreatedAt:          pack.CreatedAt,
		Identity:           pack.Identity,
		Policy:             pack.Policy,
		Effect:             pack.Effect,
		Context:            pack.Context,
		Execution:          pack.Execution,
		Receipts:           pack.Receipts,
		Reconciliation:     pack.Reconciliation,
		ReplayScript:       pack.ReplayScript,
		Provenance:         pack.Provenance,
		BundledArtifacts:   pack.BundledArtifacts,
		VerificationScopes: pack.VerificationScopes,
		HarnessTraceRefs:   pack.HarnessTraceRefs,
		EUAIActProfile:     pack.EUAIActProfile,
		Lineage:            pack.Lineage,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize evidence pack: %w", err)
	}
	return "sha256:" + canonicalize.HashBytes(data), nil
}
