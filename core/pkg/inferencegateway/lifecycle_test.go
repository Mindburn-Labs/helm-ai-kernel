package inferencegateway

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// newLedger builds an isolated balance ledger with a controllable opening
// balance for pure-lifecycle (non-engine) tests.
func newLedger(t *testing.T, openingCents int64) *BalanceLedger {
	t.Helper()
	acct := economic.NewBalanceAccount("balance-lc", "tenant-1", "USD", openingCents, "evidence://balance-lc")
	l, err := NewBalanceLedger(acct)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	return l
}

// approvedCeremony builds a sealed, dual-control approval ceremony.
func approvedCeremony(t *testing.T, requester, approver string) *contracts.ApprovalCeremony {
	t.Helper()
	now := time.Now().UTC()
	c := contracts.ApprovalCeremony{
		ApprovalID:  "appr-1",
		Subject:     "balance:balance-lc",
		Action:      "correction",
		State:       contracts.ApprovalCeremonyAllowed,
		RequestedBy: requester,
		Approvers:   []string{approver},
		Reason:      "manual correction after provider credit dispute",
		ReceiptID:   "rcpt-appr-1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	sealed, err := c.Seal()
	if err != nil {
		t.Fatalf("seal ceremony: %v", err)
	}
	return &sealed
}

// TestLifecycle_BalanceConservation walks the full lifecycle and asserts the
// running balance is conserved at every step.
func TestLifecycle_BalanceConservation(t *testing.T) {
	l := newLedger(t, 10_000)

	up, err := l.TopUp("topup-1", 5_000, "k-topup-1", "evidence://topup-1")
	if err != nil {
		t.Fatalf("topup: %v", err)
	}
	if up.BalanceAfterCents != 15_000 {
		t.Fatalf("after topup balance = %d, want 15000", up.BalanceAfterCents)
	}
	// Every movement must reference its receipt hash.
	if up.Entry.SourceContentHash != up.Receipt.ContentHash {
		t.Fatalf("topup entry does not reference receipt hash: %q != %q", up.Entry.SourceContentHash, up.Receipt.ContentHash)
	}

	promo, err := l.Promo("promo-1", 2_000, "k-promo-1", "evidence://promo-1")
	if err != nil {
		t.Fatalf("promo: %v", err)
	}
	if promo.BalanceAfterCents != 17_000 {
		t.Fatalf("after promo balance = %d, want 17000", promo.BalanceAfterCents)
	}

	// Refund must bind the usage receipt it reverses.
	ref, err := l.Refund("refund-1", 1_000, "k-refund-1", "sha256:usage-xyz", "evidence://refund-1")
	if err != nil {
		t.Fatalf("refund: %v", err)
	}
	if ref.BalanceAfterCents != 18_000 {
		t.Fatalf("after refund balance = %d, want 18000", ref.BalanceAfterCents)
	}
	if ref.Receipt.SourceReceiptHash != "sha256:usage-xyz" {
		t.Fatalf("refund did not bind source usage receipt hash")
	}
}

// TestLifecycle_IdempotentMovements proves a replayed movement key never moves
// the balance twice and never appends a second ledger entry.
func TestLifecycle_IdempotentMovements(t *testing.T) {
	l := newLedger(t, 10_000)

	first, err := l.TopUp("topup-1", 5_000, "k-dup", "evidence://topup-1")
	if err != nil {
		t.Fatalf("first topup: %v", err)
	}
	entriesAfterFirst := len(l.Entries())

	second, err := l.TopUp("topup-1-replay", 5_000, "k-dup", "evidence://topup-1")
	if err != nil {
		t.Fatalf("replay topup: %v", err)
	}
	if !second.Replayed {
		t.Fatalf("expected replay to be marked Replayed")
	}
	if second.BalanceAfterCents != first.BalanceAfterCents {
		t.Fatalf("balance moved on replay: %d != %d", second.BalanceAfterCents, first.BalanceAfterCents)
	}
	if l.BalanceCents() != 15_000 {
		t.Fatalf("balance after duplicate topup = %d, want 15000 (single apply)", l.BalanceCents())
	}
	if len(l.Entries()) != entriesAfterFirst {
		t.Fatalf("duplicate topup appended an entry: %d != %d", len(l.Entries()), entriesAfterFirst)
	}
}

// TestLifecycle_NoNegativeBalance asserts a plain usage balance cannot be driven
// negative, while enterprise invoicing permits it.
func TestLifecycle_NoNegativeBalance(t *testing.T) {
	l := newLedger(t, 1_000)
	appr := approvedCeremony(t, "ops:alice", "finance:bob")

	// A debit correction larger than the balance must be refused fail-closed.
	if _, err := l.Adjust("corr-neg", economic.SettlementDebit, 5_000, "k-corr-neg", "overcharge clawback", appr, "evidence://corr"); err == nil {
		t.Fatalf("expected debit correction beyond balance to be refused")
	}
	if l.BalanceCents() != 1_000 {
		t.Fatalf("balance changed on refused correction: %d", l.BalanceCents())
	}

	// Reservation beyond available funds is refused fail-closed.
	if _, err := l.Reserve("res-neg", 5_000, "sha256:quote-neg"); err == nil {
		t.Fatalf("expected reservation beyond available funds to be refused")
	}

	// Enable enterprise invoicing: now a debit correction may go negative.
	l.EnableEnterpriseInvoicing()
	appr2 := approvedCeremony(t, "ops:alice", "finance:bob")
	res, err := l.Adjust("corr-inv", economic.SettlementDebit, 5_000, "k-corr-inv", "deferred invoice charge", appr2, "evidence://corr2")
	if err != nil {
		t.Fatalf("invoicing correction: %v", err)
	}
	if res.BalanceAfterCents != -4_000 {
		t.Fatalf("invoicing balance = %d, want -4000", res.BalanceAfterCents)
	}
}

// TestLifecycle_CorrectionRequiresApproval proves a manual correction is rejected
// without a valid dual-control approval ceremony and accepted with one.
func TestLifecycle_CorrectionRequiresApproval(t *testing.T) {
	l := newLedger(t, 10_000)

	// No ceremony.
	if _, err := l.Adjust("corr-a", economic.SettlementCredit, 500, "k-a", "goodwill", nil, "evidence://a"); err == nil {
		t.Fatalf("expected correction without ceremony to be refused")
	}

	// Single-party "approval" (approver == requester) violates dual control.
	self := approvedCeremony(t, "ops:alice", "ops:alice")
	if _, err := l.Adjust("corr-b", economic.SettlementCredit, 500, "k-b", "goodwill", self, "evidence://b"); err == nil {
		t.Fatalf("expected self-approved correction to be refused (dual control)")
	}

	// Pending (not approved) ceremony is refused.
	pending := approvedCeremony(t, "ops:alice", "finance:bob")
	pending.State = contracts.ApprovalCeremonyPending
	resealed, err := pending.Seal()
	if err != nil {
		t.Fatalf("reseal pending: %v", err)
	}
	if _, err := l.Adjust("corr-c", economic.SettlementCredit, 500, "k-c", "goodwill", &resealed, "evidence://c"); err == nil {
		t.Fatalf("expected pending-ceremony correction to be refused")
	}

	// Valid dual-control approved correction posts an append-only ADJUSTMENT.
	ok := approvedCeremony(t, "ops:alice", "finance:bob")
	res, err := l.Adjust("corr-d", economic.SettlementCredit, 500, "k-d", "goodwill credit", ok, "evidence://d")
	if err != nil {
		t.Fatalf("valid correction: %v", err)
	}
	if res.Entry.Type != economic.UsageLedgerAdjustment {
		t.Fatalf("correction entry type = %s, want ADJUSTMENT", res.Entry.Type)
	}
	if res.BalanceAfterCents != 10_500 {
		t.Fatalf("balance after credit correction = %d, want 10500", res.BalanceAfterCents)
	}
}

// TestLifecycle_ReserveReleaseHold proves a reservation holds funds, a release
// frees them, release is idempotent, and a consumed reservation cannot be
// released.
func TestLifecycle_ReserveReleaseHold(t *testing.T) {
	l := newLedger(t, 10_000)

	res, err := l.Reserve("res-1", 3_000, "sha256:quote-1")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if l.HoldCents() != 3_000 {
		t.Fatalf("hold = %d, want 3000", l.HoldCents())
	}
	if l.AvailableCents() != 7_000 {
		t.Fatalf("available = %d, want 7000", l.AvailableCents())
	}
	_ = res

	// Idempotent reserve: same key does not double the hold.
	if _, err := l.Reserve("res-1", 3_000, "sha256:quote-1"); err != nil {
		t.Fatalf("reserve replay: %v", err)
	}
	if l.HoldCents() != 3_000 {
		t.Fatalf("hold after replay = %d, want 3000", l.HoldCents())
	}

	// Release frees the hold.
	if _, err := l.Release("res-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if l.HoldCents() != 0 {
		t.Fatalf("hold after release = %d, want 0", l.HoldCents())
	}

	// Idempotent release returns the same entry, no underflow.
	if _, err := l.Release("res-1"); err != nil {
		t.Fatalf("release replay: %v", err)
	}
	if l.HoldCents() != 0 {
		t.Fatalf("hold after double release = %d, want 0", l.HoldCents())
	}

	// A consumed reservation cannot be released.
	res2, err := l.Reserve("res-2", 2_000, "sha256:quote-2")
	if err != nil {
		t.Fatalf("reserve 2: %v", err)
	}
	_ = res2
	l.consumeReservationForDebit("res-2")
	if l.HoldCents() != 0 {
		t.Fatalf("hold after consume = %d, want 0", l.HoldCents())
	}
	if _, err := l.Release("res-2"); err == nil {
		t.Fatalf("expected release of consumed reservation to be refused")
	}
}

// TestEngine_DispatchReserveSettle proves the end-to-end happy path: a dispatch
// reserves its max cost, settlement debits the actual and drops the hold, and
// the final balance equals opening minus actual debit with no residual hold.
func TestEngine_DispatchReserveSettle(t *testing.T) {
	h := newHarness(t)

	q, err := h.engine.Quote(h.env, h.req("idem-rs", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	quote := q.Quote
	openBal := h.ledger.BalanceCents()

	res, err := h.engine.ReserveForDispatch(quote)
	if err != nil {
		t.Fatalf("reserve for dispatch: %v", err)
	}
	if res.AmountCents != quote.MaxAmountCents {
		t.Fatalf("reserved %d, want quote max %d", res.AmountCents, quote.MaxAmountCents)
	}
	if h.ledger.HoldCents() != quote.MaxAmountCents {
		t.Fatalf("hold = %d, want %d", h.ledger.HoldCents(), quote.MaxAmountCents)
	}
	// Reservation hold must be bound to the signed budget-verdict receipt.
	if res.ReceiptHash != quote.ReceiptHash || quote.ReceiptHash == "" {
		t.Fatalf("reservation not bound to quote receipt hash")
	}

	settle, err := h.engine.Settle(quote, "prov-req-rs", 2, 1000, 480)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	// Debit invariant: balance debit == provider cost + platform fee.
	if settle.UsageReceipt.BalanceDebitCents != settle.UsageReceipt.ProviderCostCents+settle.UsageReceipt.PlatformFeeCents {
		t.Fatalf("debit != provider + fee: %+v", settle.UsageReceipt)
	}
	// Settlement double-entry must balance and bind the usage receipt hash.
	if !settle.SettlementReceipt.Balanced() {
		t.Fatalf("settlement not balanced")
	}
	if settle.SettlementReceipt.SourceUsageReceiptHash != settle.UsageReceipt.ContentHash {
		t.Fatalf("settlement does not bind usage receipt hash")
	}
	if h.ledger.HoldCents() != 0 {
		t.Fatalf("hold after settle = %d, want 0 (reservation consumed)", h.ledger.HoldCents())
	}
	if h.ledger.BalanceCents() != openBal-settle.BalanceDebitCents {
		t.Fatalf("balance after settle = %d, want %d", h.ledger.BalanceCents(), openBal-settle.BalanceDebitCents)
	}
}

// TestEngine_FailedRunReleasesReservation proves a failed run frees the hold and
// leaves the balance untouched.
func TestEngine_FailedRunReleasesReservation(t *testing.T) {
	h := newHarness(t)

	q, err := h.engine.Quote(h.env, h.req("idem-fail", "gpt-4o", 1000, 500))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	openBal := h.ledger.BalanceCents()

	if _, err := h.engine.ReserveForDispatch(q.Quote); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if h.ledger.HoldCents() == 0 {
		t.Fatalf("expected a non-zero hold after reserve")
	}

	if _, err := h.engine.ReleaseReservation(q.Quote); err != nil {
		t.Fatalf("release: %v", err)
	}
	if h.ledger.HoldCents() != 0 {
		t.Fatalf("hold after failed-run release = %d, want 0", h.ledger.HoldCents())
	}
	if h.ledger.BalanceCents() != openBal {
		t.Fatalf("balance moved on failed run: %d != %d", h.ledger.BalanceCents(), openBal)
	}
	// After the reservation is released, a later settle still succeeds (consume
	// is a no-op) and posts the real debit.
	if _, err := h.engine.Settle(q.Quote, "prov-req-fail", 2, 1000, 480); err != nil {
		t.Fatalf("settle after release: %v", err)
	}
}

// TestFinanceExport_TotalsMatchLedger is the done-gate: the finance export's net
// balance delta must equal the account's actual movement, accrual totals must
// match what was accrued, and Reconciles must report balanced.
func TestFinanceExport_TotalsMatchLedger(t *testing.T) {
	h := newHarness(t)
	opening := h.ledger.BalanceCents()

	// Mixed lifecycle: top-up, a real settled debit, promo, refund, and accruals.
	if _, err := h.ledger.TopUp("topup-fx", 4_000, "k-fx-topup", "evidence://fx-topup"); err != nil {
		t.Fatalf("topup: %v", err)
	}
	if _, err := h.ledger.Promo("promo-fx", 1_500, "k-fx-promo", "evidence://fx-promo"); err != nil {
		t.Fatalf("promo: %v", err)
	}
	if _, err := h.ledger.Refund("refund-fx", 700, "k-fx-refund", "sha256:usage-fx", "evidence://fx-refund"); err != nil {
		t.Fatalf("refund: %v", err)
	}

	// A real governed debit via the engine. Use a large token estimate so the
	// quote ceiling is high enough that the actual provider cost yields a
	// non-zero platform fee without being clamped.
	q, err := h.engine.Quote(h.env, h.req("idem-fx", "gpt-4o", 100_000, 100_000))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	// providerCost=100 -> 10% platform fee=10 -> debit=110, under the 200c ceiling.
	settle, err := h.engine.Settle(q.Quote, "prov-req-fx", 100, 100_000, 100_000)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if settle.Capped {
		t.Fatalf("settle unexpectedly capped; provider cost should be under ceiling")
	}
	if settle.UsageReceipt.PlatformFeeCents == 0 {
		t.Fatalf("expected a non-zero platform fee to exercise accrual")
	}

	// Accruals (bookkeeping; must not move the cash balance).
	if _, err := h.ledger.Accrue("acc-prov", economic.BalanceMovementProviderCostAccrual, settle.UsageReceipt.ProviderCostCents, "k-acc-prov", "evidence://acc-prov"); err != nil {
		t.Fatalf("provider accrual: %v", err)
	}
	if _, err := h.ledger.Accrue("acc-fee", economic.BalanceMovementPlatformFeeAccrual, settle.UsageReceipt.PlatformFeeCents, "k-acc-fee", "evidence://acc-fee"); err != nil {
		t.Fatalf("fee accrual: %v", err)
	}

	export := h.ledger.FinanceExport()
	finalBal := h.ledger.BalanceCents()

	// Export's net balance delta must equal the actual cash movement.
	if export.NetBalanceDeltaCents != finalBal-opening {
		t.Fatalf("export net delta = %d, want %d (final %d - opening %d)", export.NetBalanceDeltaCents, finalBal-opening, finalBal, opening)
	}
	// Credits - debits identity must also reproduce the delta.
	if export.TotalCreditsCents-export.TotalDebitsCents != export.NetBalanceDeltaCents {
		t.Fatalf("credits-debits (%d) != net delta (%d)", export.TotalCreditsCents-export.TotalDebitsCents, export.NetBalanceDeltaCents)
	}
	// Accrual roll-ups must match what was accrued (debit invariant at aggregate).
	if export.ProviderCostCents != settle.UsageReceipt.ProviderCostCents {
		t.Fatalf("export provider cost = %d, want %d", export.ProviderCostCents, settle.UsageReceipt.ProviderCostCents)
	}
	if export.PlatformFeeCents != settle.UsageReceipt.PlatformFeeCents {
		t.Fatalf("export platform fee = %d, want %d", export.PlatformFeeCents, settle.UsageReceipt.PlatformFeeCents)
	}
	// Accruals must NOT have moved the cash balance.
	expectedFinal := opening + 4_000 + 1_500 + 700 - settle.BalanceDebitCents
	if finalBal != expectedFinal {
		t.Fatalf("final balance = %d, want %d (accruals must not move cash)", finalBal, expectedFinal)
	}

	rec, ok := h.ledger.Reconciles(opening, h.now, h.now.Add(time.Hour), "treasury-1")
	if !ok {
		t.Fatalf("ledger does not reconcile: %+v", rec)
	}
	if rec.Status != economic.ReconStatusMatched {
		t.Fatalf("reconciliation status = %s, want MATCHED", rec.Status)
	}
}

// TestLifecycle_AccrualDoesNotMoveBalance isolates the accrual invariant.
func TestLifecycle_AccrualDoesNotMoveBalance(t *testing.T) {
	l := newLedger(t, 10_000)
	before := l.BalanceCents()
	if _, err := l.Accrue("acc-1", economic.BalanceMovementInvoiceAccrual, 2_500, "k-acc-1", "evidence://acc-1"); err != nil {
		t.Fatalf("accrue: %v", err)
	}
	if l.BalanceCents() != before {
		t.Fatalf("accrual moved cash balance: %d != %d", l.BalanceCents(), before)
	}
	// But it is recorded as an immutable entry referencing its receipt hash.
	entries := l.Entries()
	last := entries[len(entries)-1]
	if last.SourceContentHash == "" {
		t.Fatalf("accrual entry has no source receipt hash")
	}
	// A non-accrual type must be refused by Accrue.
	if _, err := l.Accrue("acc-bad", economic.BalanceMovementTopUp, 100, "k-acc-bad", "evidence://acc-bad"); err == nil {
		t.Fatalf("expected Accrue to reject a non-accrual type")
	}
}
