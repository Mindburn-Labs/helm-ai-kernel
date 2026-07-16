package inferencegateway

import (
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// settleOne drives one governed dispatch end-to-end (quote -> settle) and returns
// the committed usage receipt, which is the internal evidence a provider invoice
// reconciles against.
func settleOne(t *testing.T, h *harness, idem, providerReqID string, providerCostCents int64) *economic.UsageReceipt {
	t.Helper()
	q, err := h.engine.Quote(h.env, h.req(idem, "gpt-4o", 100_000, 100_000))
	if err != nil {
		t.Fatalf("quote %s: %v", idem, err)
	}
	settle, err := h.engine.Settle(q.Quote, providerReqID, providerCostCents, 100_000, 100_000)
	if err != nil {
		t.Fatalf("settle %s: %v", idem, err)
	}
	if settle.UsageReceipt == nil {
		t.Fatalf("settle %s produced no usage receipt", idem)
	}
	return settle.UsageReceipt
}

// TestReconcileProviderInvoice_MatchesSettledUsage proves the engine ledger
// reconciles a provider invoice against its own settled usage receipts: matching
// lines bind the internal receipt hash and the run is MATCHED.
func TestReconcileProviderInvoice_MatchesSettledUsage(t *testing.T) {
	h := newHarness(t)
	u1 := settleOne(t, h, "idem-r1", "prov-req-r1", 100)
	u2 := settleOne(t, h, "idem-r2", "prov-req-r2", 120)

	start := h.now.Add(-time.Hour)
	inv := economic.NewProviderInvoice("inv-eng-1", "openai", "USD", "evidence://inv-eng-1", start, h.now.Add(time.Hour), []economic.ProviderInvoiceLine{
		{LineID: "l1", ProviderRequestID: "prov-req-r1", BilledCostCents: 100, Currency: "USD"},
		{LineID: "l2", ProviderRequestID: "prov-req-r2", BilledCostCents: 120, Currency: "USD"},
	})

	run, err := h.ledger.ReconcileProviderInvoice("run-eng-1", inv, "evidence://run-eng-1", h.now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if run.Status != economic.ReconStatusMatched {
		t.Fatalf("status = %s, want MATCHED; exceptions=%+v", run.Status, run.Exceptions)
	}
	if inv.Lines[0].MatchedReceiptHash != u1.ContentHash || inv.Lines[1].MatchedReceiptHash != u2.ContentHash {
		t.Fatalf("lines not bound to settled receipt hashes")
	}
	// Internal total == sum of provider costs of the settled receipts.
	if run.InternalTotalCents != 220 {
		t.Fatalf("internal total = %d, want 220", run.InternalTotalCents)
	}
}

// TestReconcileMismatch_FreezesAndRefusesSpend is the freeze-path done-gate: an
// over-billed line produces an exception, the run freezes the account per policy,
// and a frozen account refuses any new reservation/debit — without exposing keys.
func TestReconcileMismatch_FreezesAndRefusesSpend(t *testing.T) {
	h := newHarness(t)
	settleOne(t, h, "idem-f1", "prov-req-f1", 100)

	start := h.now.Add(-time.Hour)
	inv := economic.NewProviderInvoice("inv-f", "openai", "USD", "evidence://inv-f", start, h.now.Add(time.Hour), []economic.ProviderInvoiceLine{
		{LineID: "l1", ProviderRequestID: "prov-req-f1", BilledCostCents: 175, Currency: "USD"}, // over-billed
	})

	run, err := h.ledger.ReconcileProviderInvoice("run-f", inv, "evidence://run-f", h.now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if run.IsReconciled() {
		t.Fatalf("expected a discrepant run")
	}

	directive, err := h.ledger.FreezeOnReconciliation("fz-f", run, economic.FreezeScopeProvider, "evidence://fz-f")
	if err != nil {
		t.Fatalf("freeze on reconciliation: %v", err)
	}
	if directive == nil {
		t.Fatalf("expected a freeze directive for a discrepant run")
	}
	// The directive must reference the run as its source evidence and expose no key.
	if directive.SourceRef != run.ContentHash {
		t.Fatalf("directive source ref = %q, want run hash %q", directive.SourceRef, run.ContentHash)
	}
	if directive.ExposesProviderKey() {
		t.Fatalf("freeze directive must not expose a provider key")
	}
	if !h.ledger.Frozen() {
		t.Fatalf("account should be frozen after a reconciliation mismatch")
	}

	// A frozen account refuses new spend authority (reserve) and new credits.
	q, err := h.engine.Quote(h.env, h.req("idem-after-freeze", "gpt-4o", 1000, 1000))
	if err != nil {
		t.Fatalf("quote after freeze: %v", err)
	}
	if _, err := h.engine.ReserveForDispatch(q.Quote); err == nil {
		t.Fatalf("expected reservation to be refused on a frozen account")
	}
	if _, err := h.ledger.TopUp("topup-after-freeze", 1000, "k-after-freeze", "evidence://x"); err == nil {
		t.Fatalf("expected credit to be refused on a frozen account")
	}
}

// TestPaymentFailure_NoNegativeUnmanagedBalance is the SPEND6 done-gate: the
// payment-failure path must degrade spend authority WITHOUT driving an unmanaged
// balance negative and WITHOUT exposing a provider key.
func TestPaymentFailure_NoNegativeUnmanagedBalance(t *testing.T) {
	h := newHarness(t)
	// Spend some balance first so any accidental debit would be observable.
	settleOne(t, h, "idem-pf", "prov-req-pf", 100)
	before := h.ledger.BalanceCents()

	directive, err := h.ledger.RecordPaymentFailure("fz-pf", "pay-evt-123", "evidence://fz-pf", false)
	if err != nil {
		t.Fatalf("record payment failure: %v", err)
	}
	if directive.Reason != economic.FreezeReasonPaymentFailure {
		t.Fatalf("reason = %s, want PAYMENT_FAILURE", directive.Reason)
	}
	if directive.ExposesProviderKey() {
		t.Fatalf("payment-failure directive must not expose a provider key")
	}
	// Balance is unchanged and never negative.
	if after := h.ledger.BalanceCents(); after != before {
		t.Fatalf("payment failure moved the balance: %d -> %d", before, after)
	}
	if h.ledger.BalanceCents() < 0 {
		t.Fatalf("payment failure drove the balance negative")
	}
	if !h.ledger.Frozen() {
		t.Fatalf("payment failure must freeze the account")
	}
	// And a frozen account cannot be debited, so no negative balance can follow.
	q, err := h.engine.Quote(h.env, h.req("idem-pf-2", "gpt-4o", 1000, 1000))
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := h.engine.ReserveForDispatch(q.Quote); err == nil {
		t.Fatalf("frozen account must refuse new reservations")
	}
}

// TestFinanceExport_IncludesTaxBasisAndInvoiceAccrual proves the SPEND6 export
// fields (tax basis + invoice accrual) roll up from receipt-bound accrual entries
// and do not move the cash balance.
func TestFinanceExport_IncludesTaxBasisAndInvoiceAccrual(t *testing.T) {
	h := newHarness(t)
	before := h.ledger.BalanceCents()

	if _, err := h.ledger.Accrue("acc-inv", economic.BalanceMovementInvoiceAccrual, 5_000, "k-acc-inv", "evidence://acc-inv"); err != nil {
		t.Fatalf("invoice accrual: %v", err)
	}
	if _, err := h.ledger.Accrue("acc-tax", economic.BalanceMovementTaxAccrual, 1_050, "k-acc-tax", "evidence://acc-tax"); err != nil {
		t.Fatalf("tax accrual: %v", err)
	}

	export := h.ledger.FinanceExport()
	if export.InvoiceAccruedCents != 5_000 {
		t.Fatalf("invoice accrued = %d, want 5000", export.InvoiceAccruedCents)
	}
	if export.TaxBasisCents != 1_050 {
		t.Fatalf("tax basis = %d, want 1050", export.TaxBasisCents)
	}
	// Accruals must not move the cash balance (done-gate finance-export invariant).
	if h.ledger.BalanceCents() != before {
		t.Fatalf("accruals moved cash balance: %d != %d", h.ledger.BalanceCents(), before)
	}
	if export.NetBalanceDeltaCents != 0 {
		t.Fatalf("net balance delta = %d, want 0 (accruals only)", export.NetBalanceDeltaCents)
	}
}

// TestReconciliationResolution_RejectsLegacyCorrection proves an
// AMOUNT_MISMATCH cannot be resolved by a caller-constructed legacy ceremony.
func TestReconciliationResolution_RejectsLegacyCorrection(t *testing.T) {
	h := newHarness(t)
	settleOne(t, h, "idem-adj", "prov-req-adj", 100)

	start := h.now.Add(-time.Hour)
	inv := economic.NewProviderInvoice("inv-adj", "openai", "USD", "evidence://inv-adj", start, h.now.Add(time.Hour), []economic.ProviderInvoiceLine{
		{LineID: "l1", ProviderRequestID: "prov-req-adj", BilledCostCents: 130, Currency: "USD"}, // +30 over internal
	})
	run, err := h.ledger.ReconcileProviderInvoice("run-adj", inv, "evidence://run-adj", h.now)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(run.Exceptions) != 1 || run.Exceptions[0].Kind != economic.ExceptionAmountMismatch {
		t.Fatalf("expected a single AMOUNT_MISMATCH, got %+v", run.Exceptions)
	}
	delta := run.Exceptions[0].DeltaCents // 30

	entriesBefore := len(h.ledger.Entries())

	// Correction without approval is refused.
	if _, err := h.ledger.Adjust("adj-noappr", economic.SettlementDebit, delta, "k-adj-noappr", "reconciliation true-up", nil, "evidence://adj-noappr"); err == nil {
		t.Fatalf("expected unapproved correction to be refused")
	}

	// A sealed dual-control legacy ceremony remains non-authoritative.
	appr := approvedCeremony(t, "alice", "bob")
	if _, err := h.ledger.Adjust("adj-ok", economic.SettlementDebit, delta, "k-adj-ok", "reconciliation true-up for inv-adj", appr, "evidence://adj-ok"); !errors.Is(err, economic.ErrLegacyApprovalCeremonyUnsupported) {
		t.Fatalf("legacy correction error = %v, want %v", err, economic.ErrLegacyApprovalCeremonyUnsupported)
	}
	if got := len(h.ledger.Entries()); got != entriesBefore {
		t.Fatalf("legacy correction appended an entry: %d != %d", got, entriesBefore)
	}
}
