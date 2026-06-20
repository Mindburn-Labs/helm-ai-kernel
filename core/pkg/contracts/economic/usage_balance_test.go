package economic

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func sealedCeremony(t *testing.T, requester string, approvers []string, state contracts.ApprovalCeremonyState) *contracts.ApprovalCeremony {
	t.Helper()
	now := time.Now().UTC()
	c := contracts.ApprovalCeremony{
		ApprovalID:  "appr-x",
		Subject:     "balance:b1",
		Action:      "correction",
		State:       state,
		RequestedBy: requester,
		Approvers:   approvers,
		Reason:      "dispute",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	sealed, err := c.Seal()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return &sealed
}

func TestBalanceMovementReceipt_FundingValid(t *testing.T) {
	r := NewBalanceMovementReceipt("mv-1", "t1", "b1", BalanceMovementTopUp, 5_000, "USD", "k1", "evidence://mv-1")
	if err := r.Validate(); err != nil {
		t.Fatalf("topup receipt invalid: %v", err)
	}
	if r.Direction != SettlementCredit {
		t.Fatalf("topup direction = %s, want CREDIT", r.Direction)
	}
	if r.LedgerEntryType() != UsageLedgerCredit {
		t.Fatalf("topup ledger entry type = %s, want CREDIT", r.LedgerEntryType())
	}
	// Hash must be stable and change when a hash-relevant field changes.
	h1 := r.ContentHash
	r.Reason = "mutated"
	if r.Reseal() == h1 {
		t.Fatalf("expected content hash to change after mutating reason")
	}
}

func TestBalanceMovementReceipt_RefundRequiresSource(t *testing.T) {
	r := NewBalanceMovementReceipt("mv-2", "t1", "b1", BalanceMovementRefund, 1_000, "USD", "k2", "evidence://mv-2")
	if err := r.Validate(); err == nil {
		t.Fatalf("expected refund without source_receipt_hash to be invalid")
	}
	r.SourceReceiptHash = "sha256:usage-1"
	r.Reseal()
	if err := r.Validate(); err != nil {
		t.Fatalf("refund with source hash should be valid: %v", err)
	}
}

func TestBalanceMovementReceipt_CorrectionNeedsDualControl(t *testing.T) {
	base := func() *BalanceMovementReceipt {
		r := NewBalanceMovementReceipt("mv-3", "t1", "b1", BalanceMovementCorrection, 250, "USD", "k3", "evidence://mv-3")
		r.Direction = SettlementDebit
		r.Reason = "overcharge clawback"
		return r
	}

	// No approval.
	r := base()
	r.Reseal()
	if err := r.Validate(); err == nil {
		t.Fatalf("expected correction without approval to be invalid")
	}

	// Self-approval (approver == requester) is not dual control.
	r = base()
	r.Approval = sealedCeremony(t, "alice", []string{"alice"}, contracts.ApprovalCeremonyAllowed)
	r.Reseal()
	if err := r.Validate(); err == nil {
		t.Fatalf("expected self-approved correction to be invalid")
	}

	// Approved but distinct approver -> valid; entry type is ADJUSTMENT.
	r = base()
	r.Approval = sealedCeremony(t, "alice", []string{"bob"}, contracts.ApprovalCeremonyAllowed)
	r.Reseal()
	if err := r.Validate(); err != nil {
		t.Fatalf("valid dual-control correction rejected: %v", err)
	}
	if r.LedgerEntryType() != UsageLedgerAdjustment {
		t.Fatalf("correction ledger entry type = %s, want ADJUSTMENT", r.LedgerEntryType())
	}

	// Pending (not approved) ceremony is refused even with a distinct approver.
	r = base()
	r.Approval = sealedCeremony(t, "alice", []string{"bob"}, contracts.ApprovalCeremonyPending)
	r.Reseal()
	if err := r.Validate(); err == nil {
		t.Fatalf("expected pending-ceremony correction to be invalid")
	}
}

func TestBalanceMovementType_AccrualClassification(t *testing.T) {
	accruals := []BalanceMovementType{BalanceMovementProviderCostAccrual, BalanceMovementPlatformFeeAccrual, BalanceMovementInvoiceAccrual}
	for _, a := range accruals {
		if !a.IsAccrual() {
			t.Fatalf("%s should be an accrual", a)
		}
	}
	nonAccruals := []BalanceMovementType{BalanceMovementTopUp, BalanceMovementPromoCredit, BalanceMovementRefund, BalanceMovementCorrection}
	for _, n := range nonAccruals {
		if n.IsAccrual() {
			t.Fatalf("%s should not be an accrual", n)
		}
	}
}
