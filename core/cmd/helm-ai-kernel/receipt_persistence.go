package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func persistDecisionReceipt(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID string, body []byte, metadata map[string]any) error {
	return persistDecisionReceiptForTenant(ctx, svc, decision, agentID, "", body, metadata)
}

// persistDecisionReceiptForTenant may use the tenant-qualified causal-store
// capability only when the caller supplies an independently authenticated
// tenant ID. Generic paths intentionally remain unscoped rather than deriving
// a durable namespace from caller-controlled decision context.
func persistDecisionReceiptForTenant(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any) error {
	return persistDecisionReceiptForTenantWithProvenance(ctx, svc, decision, agentID, authenticatedTenantID, body, metadata, nil)
}

func persistOrganizationRuntimeDecisionReceiptForTenant(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any, provenance organizationRuntimeReceiptProvenance) error {
	return persistDecisionReceiptForTenantWithProvenance(ctx, svc, decision, agentID, authenticatedTenantID, body, metadata, &provenance)
}

func persistDecisionReceiptForTenantWithProvenance(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any, provenance *organizationRuntimeReceiptProvenance) error {
	if svc == nil || svc.ReceiptStore == nil || decision == nil {
		return fmt.Errorf("receipt persistence unavailable")
	}
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		agentID = "anonymous"
	}
	argsHash := sha256HexBytes(body)
	if metadata != nil {
		if override, ok := metadata["args_hash"].(string); ok && strings.TrimSpace(override) != "" {
			argsHash = strings.TrimSpace(override)
		}
	}
	receiptID := "rcpt_" + decision.ID
	if tenantID := strings.TrimSpace(authenticatedTenantID); tenantID != "" {
		receiptID = executor.ReceiptIDForDecision(tenantID, decision.ID)
	}
	effectID := decision.Action
	if effectID == "" {
		if action, ok := metadata["action"].(string); ok {
			effectID = action
		}
	}
	timestamp := decision.Timestamp.UTC()
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if svc.ReceiptSigner == nil {
		return fmt.Errorf("receipt signer unavailable")
	}
	decisionHash, hashErr := helmcrypto.DecisionSemanticHash(decision)
	if hashErr != nil {
		return fmt.Errorf("derive semantic decision hash: %w", hashErr)
	}
	sessionID := ""
	if decision.InputContext != nil {
		if value, ok := decision.InputContext["session_id"].(string); ok {
			sessionID = strings.TrimSpace(value)
		}
	}
	if sessionID == "" {
		sessionID = agentID
	}
	if normalizer, ok := svc.ReceiptStore.(store.ReceiptTimestampNormalizer); ok {
		// The timestamp is part of the signed V5 receipt. Normalize it before
		// signing and transparency anchoring so a durable reload retains the
		// same chain hash.
		timestamp = normalizer.NormalizeReceiptTimestamp(timestamp)
	}
	var issued *contracts.Receipt
	build := func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			ReceiptID:    receiptID,
			DecisionID:   decision.ID,
			EffectID:     effectID,
			Status:       decision.Verdict,
			BlobHash:     argsHash,
			OutputHash:   decisionHash,
			DecisionHash: decisionHash,
			Timestamp:    timestamp,
			ExecutorID:   agentID,
			Verdict:      decision.Verdict,
			ReasonCode:   decision.ReasonCode,
			PolicyHash:   decision.PolicyContentHash,
			SessionID:    sessionID,
			Metadata:     metadata,
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     argsHash,
		}
		if provenance != nil {
			attestation, err := signOrganizationRuntimeDecisionAttestation(ctx, svc, receipt, *provenance)
			if err != nil {
				return nil, err
			}
			receipt.OrganizationRuntimeDecisionAttestation = attestation
		}
		if err := svc.ReceiptSigner.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("sign receipt %s: %w", receiptID, err)
		}
		// Anchor the signed receipt hash in the transparency log before it is
		// persisted. Fail-closed: an append failure aborts the builder, which
		// rolls back AppendCausal so no receipt is stored. Degrade mode is the
		// only escape and must be explicitly enabled in config.
		if err := anchorReceiptTransparency(svc, receipt); err != nil {
			return nil, err
		}
		issued = receipt
		return receipt, nil
	}
	var err error
	if scoped, ok := svc.ReceiptStore.(store.TenantScopedCausalReceiptAppender); ok && strings.TrimSpace(authenticatedTenantID) != "" {
		err = scoped.AppendCausalScoped(ctx, strings.TrimSpace(authenticatedTenantID), sessionID, build)
	} else {
		err = svc.ReceiptStore.AppendCausal(ctx, sessionID, build)
	}
	if err != nil {
		return fmt.Errorf("store receipt %s: %w", receiptID, err)
	}
	if err := writePortableEvaluateEvidencePack(svc, issued); err != nil {
		return fmt.Errorf("write portable evaluate evidence pack %s: %w", receiptID, err)
	}
	return nil
}

// TransparencyAppender is the subset of the receipt transparency log needed at
// issuance time: append a receipt-hash leaf and report its assigned index.
type TransparencyAppender interface {
	Append(leafInput []byte) (uint64, error)
}

// anchorReceiptTransparency appends the signed receipt's content hash to the
// transparency log and records the resulting leaf on the receipt. It is
// fail-closed by default: if the log is configured but the append fails,
// issuance is aborted. When svc.TranspLogDegrade is set, an append failure
// instead records a deferred anchor so the receipt can be backfilled later.
// A nil log leaves the receipt unanchored (no transparency configured).
func anchorReceiptTransparency(svc *Services, receipt *contracts.Receipt) error {
	if svc == nil || svc.TranspLog == nil {
		return nil
	}
	leafHashHex, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		return fmt.Errorf("transparency leaf hash for %s: %w", receipt.ReceiptID, err)
	}
	leafInput, err := hex.DecodeString(leafHashHex)
	if err != nil {
		return fmt.Errorf("decode transparency leaf hash for %s: %w", receipt.ReceiptID, err)
	}
	index, appendErr := svc.TranspLog.Append(leafInput)
	if appendErr != nil {
		if !svc.TranspLogDegrade {
			return fmt.Errorf("transparency log append for %s: %w", receipt.ReceiptID, appendErr)
		}
		receipt.LogID = svc.TranspLogID
		receipt.Transparency = &contracts.TransparencyAnchor{
			Backend:  "translog",
			LogID:    svc.TranspLogID,
			Deferred: true,
		}
		return nil
	}
	receipt.LogID = svc.TranspLogID
	receipt.LeafIndex = index
	receipt.Transparency = &contracts.TransparencyAnchor{
		Backend: "translog",
		LogID:   svc.TranspLogID,
	}
	return nil
}

func receiptLinkHash(receipt *contracts.Receipt) string {
	if hash, err := contracts.ReceiptChainHash(receipt); err == nil {
		return hash
	}
	if receipt.MerkleRoot != "" {
		return sha256HexBytes([]byte(receipt.MerkleRoot))
	}
	return sha256HexBytes([]byte(receipt.ReceiptID))
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
