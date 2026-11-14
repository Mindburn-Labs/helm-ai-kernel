// quantum_posture: test-only historical receipt builders use canonical hashes.

package evidencepack

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"time"
)

func fixtureNewRouteQuote(id, tenantID, spendIntentID, envelopeID, agentID string, selected economic.ModelRoute, quotedAmountCents, maxAmountCents int64, currency, routePolicyHash string, expiresAt time.Time, decision economic.SpendAuthorityDecision) *economic.RouteQuote {
	q := &economic.RouteQuote{
		ID:                        id,
		TenantID:                  tenantID,
		SpendIntentID:             spendIntentID,
		EnvelopeID:                envelopeID,
		AgentID:                   agentID,
		RequestedProviderID:       selected.ProviderID,
		RequestedModelID:          selected.ModelID,
		SelectedProviderID:        selected.ProviderID,
		SelectedModelID:           selected.ModelID,
		ProviderPriceSnapshotHash: selected.PriceSnapshotHash,
		QuotedAmountCents:         quotedAmountCents,
		MaxAmountCents:            maxAmountCents,
		Currency:                  currency,
		RoutePolicyHash:           routePolicyHash,
		BudgetVerdict:             decision.Verdict,
		ReasonCode:                decision.ReasonCode,
		CreatedAt:                 time.Now().UTC(),
		ExpiresAt:                 expiresAt,
	}
	q.ContentHash = q.CanonicalContentHash()
	return q
}

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

func fixtureNewUsageReceipt(id, tenantID, routeQuoteID, spendIntentID, envelopeID, agentID, providerID, modelID string, quotedAmountCents, providerCostCents, platformFeeCents int64, currency, policyHash, evidencePackRef string) *economic.UsageReceipt {
	actualAmountCents := providerCostCents + platformFeeCents
	r := &economic.UsageReceipt{
		ID:                id,
		TenantID:          tenantID,
		RouteQuoteID:      routeQuoteID,
		SpendIntentID:     spendIntentID,
		EnvelopeID:        envelopeID,
		AgentID:           agentID,
		ProviderID:        providerID,
		ModelID:           modelID,
		QuotedAmountCents: quotedAmountCents,
		ActualAmountCents: actualAmountCents,
		ProviderCostCents: providerCostCents,
		PlatformFeeCents:  platformFeeCents,
		BalanceDebitCents: actualAmountCents,
		Currency:          currency,
		BudgetVerdict:     economic.BudgetVerdictAllow,
		ReasonCode:        economic.SpendReasonOKWithinEnvelope,
		PolicyHash:        policyHash,
		EvidencePackRef:   evidencePackRef,
		CreatedAt:         time.Now().UTC(),
	}
	r.ContentHash = r.CanonicalContentHash()
	return r
}

func fixtureNewSettlementReceipt(id, tenantID, usageReceiptID, routeQuoteID, treasuryAccountID, sourceUsageReceiptHash, currency, evidencePackRef string, entries []economic.SettlementLedgerEntry) *economic.SettlementReceipt {
	s := &economic.SettlementReceipt{
		ID:                     id,
		TenantID:               tenantID,
		UsageReceiptID:         usageReceiptID,
		RouteQuoteID:           routeQuoteID,
		TreasuryAccountID:      treasuryAccountID,
		SourceUsageReceiptHash: sourceUsageReceiptHash,
		LedgerEntries:          entries,
		Currency:               currency,
		EvidencePackRef:        evidencePackRef,
		CreatedAt:              time.Now().UTC(),
	}
	s.ContentHash = s.CanonicalContentHash()
	return s
}
