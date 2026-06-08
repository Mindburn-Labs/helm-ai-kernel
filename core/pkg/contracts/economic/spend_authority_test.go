package economic

import (
	"strings"
	"testing"
	"time"
)

func TestAgentSpendEnvelopeEvaluateSpend(t *testing.T) {
	envelope := spendAuthorityTestEnvelope()

	decision := envelope.EvaluateSpend(100, "openai", "gpt-5-mini")
	if decision.Verdict != BudgetVerdictAllow {
		t.Fatalf("verdict = %s, want ALLOW", decision.Verdict)
	}
	if decision.ReasonCode != SpendReasonOKWithinEnvelope {
		t.Fatalf("reason = %s, want %s", decision.ReasonCode, SpendReasonOKWithinEnvelope)
	}
	if !strings.HasPrefix(decision.ContentHash, "sha256:") {
		t.Fatalf("decision content hash = %q, want sha256 prefix", decision.ContentHash)
	}

	approval := envelope.EvaluateSpend(800, "openai", "gpt-5-mini")
	if approval.Verdict != BudgetVerdictEscalate || approval.ReasonCode != SpendReasonApprovalRequired {
		t.Fatalf("approval decision = (%s, %s), want ESCALATE approval", approval.Verdict, approval.ReasonCode)
	}

	envelope.EmergencyStop = true
	denied := envelope.EvaluateSpend(100, "openai", "gpt-5-mini")
	if denied.Verdict != BudgetVerdictDeny || denied.ReasonCode != SpendReasonEmergencyStop {
		t.Fatalf("emergency decision = (%s, %s), want DENY emergency", denied.Verdict, denied.ReasonCode)
	}

	var missing *AgentSpendEnvelope
	missingDecision := missing.EvaluateSpend(100, "openai", "gpt-5-mini")
	if missingDecision.ReasonCode != SpendReasonEnvelopeNotFound {
		t.Fatalf("missing envelope reason = %s, want %s", missingDecision.ReasonCode, SpendReasonEnvelopeNotFound)
	}
}

func TestSpendAuthorityDecisionCanonicalContentHash(t *testing.T) {
	decision := spendAuthorityTestEnvelope().EvaluateSpend(100, "openai", "gpt-5-mini")
	if decision.CanonicalContentHash() != decision.ContentHash {
		t.Fatalf("canonical decision hash = %s, want %s", decision.CanonicalContentHash(), decision.ContentHash)
	}
	if !decision.HasCanonicalContentHash() {
		t.Fatal("decision should report a canonical content hash")
	}
	decision.ContentHash = "sha256:tampered"
	if decision.HasCanonicalContentHash() {
		t.Fatal("tampered decision hash should not validate")
	}
}

func TestAgentSpendEnvelopeEvaluateSpendValidityWindow(t *testing.T) {
	envelope := spendAuthorityTestEnvelope()
	envelope.EffectiveAt = time.Now().UTC().Add(time.Hour)
	envelope.ContentHash = envelope.computeHash()
	decision := envelope.EvaluateSpend(100, "openai", "gpt-5-mini")
	if decision.Verdict != BudgetVerdictDeny || decision.ReasonCode != SpendReasonEnvelopeNotYetEffective {
		t.Fatalf("future envelope decision = (%s, %s), want DENY not-yet-effective", decision.Verdict, decision.ReasonCode)
	}

	envelope = spendAuthorityTestEnvelope()
	expired := time.Now().UTC().Add(-time.Second)
	envelope.ExpiresAt = &expired
	envelope.ContentHash = envelope.computeHash()
	decision = envelope.EvaluateSpend(100, "openai", "gpt-5-mini")
	if decision.Verdict != BudgetVerdictDeny || decision.ReasonCode != SpendReasonEnvelopeExpired {
		t.Fatalf("expired envelope decision = (%s, %s), want DENY expired", decision.Verdict, decision.ReasonCode)
	}
}

func TestAgentSpendEnvelopeValidationAndDeterministicHash(t *testing.T) {
	a := spendAuthorityTestEnvelope()
	b := spendAuthorityTestEnvelope()
	if a.ContentHash != b.ContentHash {
		t.Fatalf("content hash = %s vs %s, want deterministic", a.ContentHash, b.ContentHash)
	}

	cases := []struct {
		name    string
		mutate  func(*AgentSpendEnvelope)
		wantErr string
	}{
		{"valid", func(*AgentSpendEnvelope) {}, ""},
		{"missing id", func(e *AgentSpendEnvelope) { e.ID = "" }, "id is required"},
		{"missing tenant", func(e *AgentSpendEnvelope) { e.TenantID = "" }, "tenant_id is required"},
		{"missing agent", func(e *AgentSpendEnvelope) { e.AgentID = "" }, "agent_id is required"},
		{"missing principal", func(e *AgentSpendEnvelope) { e.PrincipalID = "" }, "principal_id is required"},
		{"missing budget", func(e *AgentSpendEnvelope) { e.BudgetID = "" }, "budget_id is required"},
		{"nonpositive max", func(e *AgentSpendEnvelope) { e.MaxAmountCents = 0 }, "max_amount_cents must be positive"},
		{"overspent", func(e *AgentSpendEnvelope) { e.UsedAmountCents = 900; e.ReservedAmountCents = 200 }, "used plus reserved exceeds"},
		{"empty providers", func(e *AgentSpendEnvelope) { e.AllowedProviders = nil }, "at least one allowed provider"},
		{"empty models", func(e *AgentSpendEnvelope) { e.AllowedModels = nil }, "at least one allowed model"},
		{"missing policy", func(e *AgentSpendEnvelope) { e.PolicyHash = "" }, "policy_hash is required"},
		{"reversed validity", func(e *AgentSpendEnvelope) {
			expires := e.EffectiveAt.Add(-time.Second)
			e.ExpiresAt = &expires
		}, "expires_at must be after effective_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := spendAuthorityTestEnvelope()
			tc.mutate(envelope)
			err := envelope.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			requireEconomicErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestRouteQuoteValidationAndExpiry(t *testing.T) {
	envelope := spendAuthorityTestEnvelope()
	decision := envelope.EvaluateSpend(100, "openai", "gpt-5-mini")
	quote := spendAuthorityTestQuote(decision)
	if err := quote.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if quote.Expired(quote.CreatedAt.Add(time.Minute)) {
		t.Fatal("quote expired before expires_at")
	}
	if !quote.Expired(quote.ExpiresAt) {
		t.Fatal("quote should expire at expires_at")
	}

	quote.QuotedAmountCents = quote.MaxAmountCents + 1
	requireEconomicErrorContains(t, quote.Validate(), "quoted_amount_cents exceeds")

	quote = spendAuthorityTestQuote(decision)
	quote.ModelSubstituted = true
	requireEconomicErrorContains(t, quote.Validate(), "fallback_chain is required")
}

func TestUsageReceiptValidationAndSettlementRequirements(t *testing.T) {
	receipt := spendAuthorityTestUsageReceipt()
	receipt.SettlementReceiptHash = "sha256:settlement"
	receipt.LedgerEntryIDs = []string{"ledger-debit", "ledger-credit"}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	receipt.ActualAmountCents++
	requireEconomicErrorContains(t, receipt.Validate(), "actual_amount_cents must equal")

	receipt = spendAuthorityTestUsageReceipt()
	receipt.SettlementReceiptHash = "sha256:settlement"
	receipt.LedgerEntryIDs = []string{"ledger-debit", "ledger-credit"}
	receipt.EvidencePackRef = ""
	requireEconomicErrorContains(t, receipt.Validate(), "evidence_pack_ref is required")

	receipt = spendAuthorityTestUsageReceipt()
	receipt.LedgerEntryIDs = []string{"ledger-debit"}
	requireEconomicErrorContains(t, receipt.Validate(), "settlement_receipt_hash is required")
}

func TestSettlementReceiptValidationBalanceAndHash(t *testing.T) {
	settlement := spendAuthorityTestSettlementReceipt()
	if err := settlement.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if !settlement.Balanced() {
		t.Fatal("settlement should be balanced")
	}
	if !strings.HasPrefix(settlement.ContentHash, "sha256:") {
		t.Fatalf("content hash = %q, want sha256 prefix", settlement.ContentHash)
	}

	settlement.LedgerEntries[1].AmountCents = 201
	if settlement.Balanced() {
		t.Fatal("mutated settlement should be unbalanced")
	}
	requireEconomicErrorContains(t, settlement.Validate(), "ledger entries are not balanced")

	settlement = spendAuthorityTestSettlementReceipt()
	settlement.LedgerEntries[0].Currency = "EUR"
	requireEconomicErrorContains(t, settlement.Validate(), "currency must match")
}

func spendAuthorityTestEnvelope() *AgentSpendEnvelope {
	envelope := NewAgentSpendEnvelope(
		"env-1",
		"tenant-1",
		"agent-1",
		"user-1",
		"budget-1",
		"USD",
		SpendPeriodMonthly,
		1000,
		900,
		"sha256:policy",
	)
	envelope.AllowedProviders = []string{"openai", "anthropic"}
	envelope.AllowedModels = []string{"gpt-5-mini", "claude-sonnet-4"}
	envelope.ApprovalRequiredAboveCents = 750
	envelope.ContentHash = envelope.computeHash()
	return envelope
}

func spendAuthorityTestQuote(decision SpendAuthorityDecision) *RouteQuote {
	return NewRouteQuote(
		"quote-1",
		"tenant-1",
		"spend-1",
		"env-1",
		"agent-1",
		ModelRoute{ProviderID: "openai", ModelID: "gpt-5-mini", PriceSnapshotHash: "sha256:price"},
		100,
		200,
		"USD",
		"sha256:route-policy",
		time.Now().UTC().Add(5*time.Minute),
		decision,
	)
}

func spendAuthorityTestUsageReceipt() *UsageReceipt {
	receipt := NewUsageReceipt(
		"usage-1",
		"tenant-1",
		"quote-1",
		"spend-1",
		"env-1",
		"agent-1",
		"openai",
		"gpt-5-mini",
		100,
		180,
		20,
		"USD",
		"sha256:policy",
		"evidence://pack-1",
	)
	receipt.ProviderRequestID = "req-1"
	receipt.ProviderPriceSnapshotHash = "sha256:price"
	receipt.ContentHash = receipt.computeHash()
	return receipt
}

func spendAuthorityTestSettlementReceipt() *SettlementReceipt {
	return NewSettlementReceipt(
		"settlement-1",
		"tenant-1",
		"usage-1",
		"quote-1",
		"treasury-1",
		"sha256:usage",
		"USD",
		"evidence://pack-1",
		[]SettlementLedgerEntry{
			{
				ID:          "ledger-debit",
				AccountID:   "tenant-balance",
				Direction:   SettlementDebit,
				AmountCents: 200,
				Currency:    "USD",
			},
			{
				ID:          "ledger-credit",
				AccountID:   "provider-payable",
				Direction:   SettlementCredit,
				AmountCents: 200,
				Currency:    "USD",
			},
		},
	)
}
