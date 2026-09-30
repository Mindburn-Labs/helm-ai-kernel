package evidencepack

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

func exactSpendFixture(t *testing.T, zero bool) SpendReceiptSet {
	t.Helper()
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	p := &economic.ProviderPriceSnapshot{SchemaVersion: economic.ProviderPriceSchemaV2, ID: "price-1", ProviderID: "typesafe", ModelID: "jev-fixture", Currency: "USD", InputTokenNanoCents: 4200, ProviderTermsProfileID: "terms-1", SourceURI: "test://fixture", SourceHash: digest, CapturedAt: now, EffectiveAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	tokens, amount := int64(1), int64(4200)
	if zero {
		tokens, amount = 0, 0
	}
	u := &economic.UsageReceiptV2{SchemaVersion: economic.UsageReceiptSchemaV2, ID: "usage-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", RouteQuoteID: "quote-1", SpendIntentID: "intent-1", EnvelopeID: "envelope-1", AgentID: "agent-1", ProviderID: p.ProviderID, ModelID: p.ModelID, ProviderRequestID: "request-1", ProviderPriceSnapshotHash: p.ContentHash, ObservationDigest: digest, ReservedNanoCents: economic.NanoCentsPerCent, AccruedNanoCents: amount, Currency: "USD", CostBasis: economic.TariffEstimateBasis, InputTokens: tokens, PolicyHash: digest, EvidencePackRef: "evidence:1", CreatedAt: now}
	if err := u.Seal(); err != nil {
		t.Fatal(err)
	}
	s := &economic.SettlementReceiptV2{SchemaVersion: economic.SettlementReceiptSchemaV2, ID: "settlement-1", TenantID: u.TenantID, WorkspaceID: u.WorkspaceID, UsageReceiptID: u.ID, RouteQuoteID: u.RouteQuoteID, SourceUsageReceiptHash: u.ContentHash, ReservedNanoCents: u.ReservedNanoCents, AccruedNanoCents: amount, Currency: "USD", CostBasis: economic.TariffEstimateBasis, LedgerEntries: []economic.SettlementLedgerEntryV2{}, EvidencePackRef: u.EvidencePackRef, CreatedAt: now}
	if !zero {
		s.LedgerEntries = []economic.SettlementLedgerEntryV2{{ID: "debit-1", AccountID: "account-1", Direction: economic.SettlementDebit, AmountNanoCents: amount}, {ID: "credit-1", AccountID: "accrual-1", Direction: economic.SettlementCredit, AmountNanoCents: amount}}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	return SpendReceiptSet{UsageV2: u, SettlementV2: s, PriceV2: p}
}

func TestExactSpendEvidenceOffline(t *testing.T) {
	for _, zero := range []bool{false, true} {
		set := exactSpendFixture(t, zero)
		_, contents, err := BuildSpendEvidencePack("exact-pack", "actor-1", "intent-1", set.UsageV2.PolicyHash, set, economic.DefaultRedactionProfile())
		if err != nil {
			t.Fatal(err)
		}
		result, err := VerifySpendEvidenceOffline(contents)
		if err != nil || !result.OK || len(result.ReceiptsVerified) != 3 {
			t.Fatalf("exact pack failed: %+v %v", result, err)
		}
	}
}

func TestExactSpendEvidenceRejectsTamperingAndMixedVersions(t *testing.T) {
	for _, mutate := range []func(map[string][]byte){
		func(c map[string][]byte) { delete(c, spendPriceV2Path) },
		func(c map[string][]byte) {
			c[spendUsageReceiptPath] = []byte(strings.Replace(string(c[spendUsageReceiptPath]), `"input_tokens":"1"`, `"input_tokens":"2"`, 1))
		},
		func(c map[string][]byte) { c[spendSettlementReceiptPath] = []byte(`{"schema_version":"future"}`) },
		func(c map[string][]byte) { c[spendSettlementReceiptPath] = []byte(`{}`) },
		func(c map[string][]byte) { c[spendUsageReceiptPath] = []byte(`{}`) },
	} {
		set := exactSpendFixture(t, false)
		c := map[string][]byte{}
		c[spendUsageReceiptPath], _ = json.Marshal(set.UsageV2)
		c[spendSettlementReceiptPath], _ = json.Marshal(set.SettlementV2)
		c[spendPriceV2Path], _ = json.Marshal(set.PriceV2)
		mutate(c)
		var invariants []string
		if _, err := verifySpendReceipts(c, &invariants); err == nil {
			t.Fatal("invalid exact receipts verified")
		}
	}
	set := exactSpendFixture(t, false)
	set.Usage = &economic.UsageReceipt{}
	if _, _, err := BuildSpendEvidencePack("mixed", "actor", "intent", "policy", set, economic.DefaultRedactionProfile()); err == nil {
		t.Fatal("mixed receipt builder accepted")
	}
}

func TestExactSpendEvidenceRejectsResealedFalseAccrual(t *testing.T) {
	set := exactSpendFixture(t, false)
	set.UsageV2.AccruedNanoCents++
	if err := set.UsageV2.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := BuildSpendEvidencePack("false", "actor", "intent", "policy", set, economic.DefaultRedactionProfile()); err == nil {
		t.Fatal("arithmetic falsehood accepted after reseal")
	}
}
