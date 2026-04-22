package researchruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

func CanonicalHash(v any) (string, error) {
	data, err := canonicalize.JCS(v)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func BuildTraceHash(trace TracePack) (string, error) {
	return CanonicalHash(trace)
}

func BuildPromotionReceipt(receipt PromotionReceipt) (PromotionReceipt, error) {
	hash, err := CanonicalHash(struct {
		ReceiptID        string           `json:"receipt_id"`
		MissionID        string           `json:"mission_id"`
		PublicationID    string           `json:"publication_id"`
		PublicationState PublicationState `json:"publication_state"`
		EvidencePackHash string           `json:"evidence_pack_hash"`
		RequestedModel   string           `json:"requested_model,omitempty"`
		ActualModel      string           `json:"actual_model,omitempty"`
		FallbackUsed     bool             `json:"fallback_used"`
		PolicyDecision   string           `json:"policy_decision"`
		ReasonCodes      []string         `json:"reason_codes,omitempty"`
		Signer           string           `json:"signer,omitempty"`
		CreatedAt        int64            `json:"created_at"`
	}{
		ReceiptID:        receipt.ReceiptID,
		MissionID:        receipt.MissionID,
		PublicationID:    receipt.PublicationID,
		PublicationState: receipt.PublicationState,
		EvidencePackHash: receipt.EvidencePackHash,
		RequestedModel:   receipt.RequestedModel,
		ActualModel:      receipt.ActualModel,
		FallbackUsed:     receipt.FallbackUsed,
		PolicyDecision:   receipt.PolicyDecision,
		ReasonCodes:      append([]string(nil), receipt.ReasonCodes...),
		Signer:           receipt.Signer,
		CreatedAt:        receipt.CreatedAt.Unix(),
	})
	if err != nil {
		return PromotionReceipt{}, err
	}
	receipt.ManifestHash = hash
	return receipt, nil
}

func VerifyPromotionReceipt(receipt PromotionReceipt) error {
	expected, err := BuildPromotionReceipt(PromotionReceipt{
		ReceiptID:        receipt.ReceiptID,
		MissionID:        receipt.MissionID,
		PublicationID:    receipt.PublicationID,
		PublicationState: receipt.PublicationState,
		EvidencePackHash: receipt.EvidencePackHash,
		RequestedModel:   receipt.RequestedModel,
		ActualModel:      receipt.ActualModel,
		FallbackUsed:     receipt.FallbackUsed,
		PolicyDecision:   receipt.PolicyDecision,
		ReasonCodes:      append([]string(nil), receipt.ReasonCodes...),
		Signer:           receipt.Signer,
		CreatedAt:        receipt.CreatedAt,
	})
	if err != nil {
		return err
	}
	if expected.ManifestHash != receipt.ManifestHash {
		return fmt.Errorf("manifest hash mismatch: expected %s got %s", expected.ManifestHash, receipt.ManifestHash)
	}
	return nil
}
