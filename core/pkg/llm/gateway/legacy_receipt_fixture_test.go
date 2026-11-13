// quantum_posture: test-only historical receipt builders use canonical hashes.

package gateway

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"time"
)

func fixtureNewBudgetVerdictReceipt(id, tenantID, spendIntentID, envelopeID, agentID, providerID, modelID string, quotedAmountCents, maxAmountCents int64, currency, providerPriceSnapshotHash, routePolicyHash, evidencePackRef string, decision economic.SpendAuthorityDecision) *economic.BudgetVerdictReceipt {
	r := &economic.BudgetVerdictReceipt{
		ID:                        id,
		TenantID:                  tenantID,
		SpendIntentID:             spendIntentID,
		EnvelopeID:                envelopeID,
		AgentID:                   agentID,
		ProviderID:                providerID,
		ModelID:                   modelID,
		ProviderPriceSnapshotHash: providerPriceSnapshotHash,
		QuotedAmountCents:         quotedAmountCents,
		MaxAmountCents:            maxAmountCents,
		Currency:                  currency,
		BudgetVerdict:             decision.Verdict,
		ReasonCode:                decision.ReasonCode,
		DecisionHash:              decision.ContentHash,
		EnvelopeHash:              decision.EnvelopeHash,
		RoutePolicyHash:           routePolicyHash,
		EvidencePackRef:           evidencePackRef,
		CreatedAt:                 time.Now().UTC(),
	}
	r.ContentHash = r.CanonicalContentHash()
	return r
}
