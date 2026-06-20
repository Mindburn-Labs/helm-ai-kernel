package economic

import (
	"strings"
	"testing"
	"time"
)

func TestProviderTermsProfileValidationRedlines(t *testing.T) {
	profile := NewProviderTermsProfile("terms-1", "openai", ProviderAccountDirect, "2026-01-01", "legal-review-1")
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if !strings.HasPrefix(profile.ContentHash, "sha256:") {
		t.Fatalf("content hash = %q, want sha256 prefix", profile.ContentHash)
	}

	cases := []struct {
		name    string
		mutate  func(*ProviderTermsProfile)
		wantErr string
	}{
		{"usage resale", func(p *ProviderTermsProfile) { p.AllowsUsageResale = true }, "usage resale is forbidden"},
		{"credit transfer", func(p *ProviderTermsProfile) { p.AllowsProviderCreditTransfer = true }, "provider credit transfer is forbidden"},
		{"cash redemption", func(p *ProviderTermsProfile) { p.AllowsProviderCreditCashRedemption = true }, "provider credit cash redemption is forbidden"},
		{"managed missing contract", func(p *ProviderTermsProfile) {
			p.AccountMode = ProviderAccountManagedOrgAccount
			p.RequiresContractForManagedBilling = true
		}, "contract_ref is required"},
		{"missing legal", func(p *ProviderTermsProfile) { p.LegalReviewRef = "" }, "legal_review_ref is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProviderTermsProfile("terms-1", "openai", ProviderAccountDirect, "2026-01-01", "legal-review-1")
			tc.mutate(p)
			requireEconomicErrorContains(t, p.Validate(), tc.wantErr)
		})
	}
}

func TestProviderPriceSnapshotValidationAndStaleness(t *testing.T) {
	now := time.Now().UTC()
	snapshot := NewProviderPriceSnapshot("price-1", "openai", "gpt-5-mini", "USD", "terms-1", "sha256:source", now, now.Add(time.Hour))
	snapshot.InputTokenMicroCents = 10
	snapshot.OutputTokenMicroCents = 80
	snapshot.ContentHash = snapshot.computeHash()

	if err := snapshot.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if snapshot.Stale(now.Add(30 * time.Minute)) {
		t.Fatal("snapshot should not be stale before expiry")
	}
	if !snapshot.Stale(snapshot.ExpiresAt) {
		t.Fatal("snapshot should be stale at expires_at")
	}

	snapshot.InputTokenMicroCents = 0
	snapshot.OutputTokenMicroCents = 0
	requireEconomicErrorContains(t, snapshot.Validate(), "at least one price field is required")

	snapshot = NewProviderPriceSnapshot("price-1", "openai", "gpt-5-mini", "USD", "terms-1", "sha256:source", now, now)
	snapshot.RequestCents = 1
	requireEconomicErrorContains(t, snapshot.Validate(), "expires_at must be after effective_at")
}

func TestProviderPriceSnapshotQuoteCents(t *testing.T) {
	now := time.Now().UTC()
	s := NewProviderPriceSnapshot("price-1", "openai", "gpt-4o", "USD", "terms-1", "sha256:source", now, now.Add(time.Hour))
	s.InputTokenMicroCents = 500   // 0.0005 cents/token
	s.OutputTokenMicroCents = 1500 // 0.0015 cents/token

	// 1000*500 + 500*1500 = 1_250_000 micro-cents -> ceil to 2 cents.
	got, err := s.QuoteCents(1000, 500)
	if err != nil {
		t.Fatalf("QuoteCents() = %v, want nil", err)
	}
	if got != 2 {
		t.Fatalf("QuoteCents(1000,500) = %d, want 2", got)
	}

	// Sub-cent usage must round UP so a quote never under-charges.
	got, err = s.QuoteCents(1, 0) // 500 micro-cents -> 1 cent
	if err != nil {
		t.Fatalf("QuoteCents() = %v", err)
	}
	if got != 1 {
		t.Fatalf("QuoteCents(1,0) = %d, want 1 (round up)", got)
	}

	// Flat request surcharge is added on top of token cost.
	s.RequestCents = 3
	got, err = s.QuoteCents(0, 0) // 0 token micro-cents + 3 flat
	if err != nil {
		t.Fatalf("QuoteCents() = %v", err)
	}
	if got != 3 {
		t.Fatalf("QuoteCents(0,0) with surcharge = %d, want 3", got)
	}

	// Negative token counts are rejected.
	if _, err := s.QuoteCents(-1, 0); err == nil {
		t.Fatal("QuoteCents with negative tokens must error")
	}

	// A zero-priced request must not produce a non-positive quote.
	zero := NewProviderPriceSnapshot("price-z", "openai", "gpt-4o", "USD", "terms-1", "sha256:source", now, now.Add(time.Hour))
	zero.InputTokenMicroCents = 1
	if _, err := zero.QuoteCents(0, 0); err == nil {
		t.Fatal("QuoteCents must reject a zero total")
	}
}

func TestBalanceAccountValidationAndAvailability(t *testing.T) {
	account := NewBalanceAccount("balance-1", "tenant-1", "USD", 1000, "evidence://pack-1")
	account.HoldCents = 250
	account.ContentHash = account.computeHash()
	if account.AvailableCents() != 750 {
		t.Fatalf("AvailableCents = %d, want 750", account.AvailableCents())
	}
	if err := account.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	account.Status = BalanceAccountFrozen
	if account.AvailableCents() != 0 {
		t.Fatal("frozen account should have zero available cents")
	}

	account = NewBalanceAccount("balance-1", "tenant-1", "USD", 1000, "evidence://pack-1")
	account.HoldCents = 1001
	requireEconomicErrorContains(t, account.Validate(), "hold_cents cannot exceed")

	account = NewBalanceAccount("balance-1", "tenant-1", "USD", 1000, "evidence://pack-1")
	account.CreditLimitCents = 100
	requireEconomicErrorContains(t, account.Validate(), "credit_line_id is required")
}

func TestUsageLedgerEntryValidation(t *testing.T) {
	entry := NewUsageLedgerEntry(
		"ledger-1",
		"tenant-1",
		"balance-1",
		UsageLedgerDebit,
		SettlementDebit,
		100,
		"USD",
		SpendReasonOKWithinEnvelope,
		"sha256:usage",
	)
	entry.UsageReceiptID = "usage-1"
	entry.ContentHash = entry.computeHash()
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	entry.UsageReceiptID = ""
	requireEconomicErrorContains(t, entry.Validate(), "usage_receipt_id is required")

	entry = NewUsageLedgerEntry("ledger-1", "tenant-1", "balance-1", UsageLedgerCredit, SettlementCredit, 100, "USD", SpendReasonOKWithinEnvelope, "sha256:source")
	if err := entry.Validate(); err != nil {
		t.Fatalf("credit entry Validate() = %v, want nil", err)
	}
}

func TestCapacityCommitmentRequiresContractEvidenceWhenActive(t *testing.T) {
	start := time.Now().UTC()
	commitment := NewCapacityCommitment("commit-1", "tenant-1", "openai", "USD", 1000, start, start.Add(24*time.Hour))
	if commitment.RemainingCents() != 1000 {
		t.Fatalf("RemainingCents = %d, want 1000", commitment.RemainingCents())
	}
	if err := commitment.Validate(); err != nil {
		t.Fatalf("draft Validate() = %v, want nil", err)
	}

	commitment.Status = CapacityCommitmentActive
	requireEconomicErrorContains(t, commitment.Validate(), "contract_ref is required")

	commitment.ContractRef = "contract://provider/openai/2026"
	requireEconomicErrorContains(t, commitment.Validate(), "evidence_pack_ref is required")

	commitment.EvidencePackRef = "evidence://pack-1"
	if err := commitment.Validate(); err != nil {
		t.Fatalf("active Validate() = %v, want nil", err)
	}
}

func TestDeferredCreditLineCannotBeRuntimeUsable(t *testing.T) {
	creditLine := NewDeferredCreditLine("credit-1", "tenant-1", "USD")
	if err := creditLine.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if creditLine.RuntimeUsable {
		t.Fatal("deferred credit line should not be runtime usable")
	}

	creditLine.RuntimeUsable = true
	requireEconomicErrorContains(t, creditLine.Validate(), "runtime_usable must be false")

	creditLine = NewDeferredCreditLine("credit-1", "tenant-1", "USD")
	creditLine.Status = CreditLineStatus("ACTIVE")
	requireEconomicErrorContains(t, creditLine.Validate(), "only DEFERRED status is allowed")
}
