package economic

import (
	"testing"
	"time"
)

// usageReceiptFor builds a minimal valid UsageReceipt for a provider request so
// reconciliation has a real internal-side content hash to bind against.
func usageReceiptFor(t *testing.T, id, providerRequestID string, providerCostCents int64) *UsageReceipt {
	t.Helper()
	r := NewUsageReceipt(id, "tenant-1", "rq-"+id, "si-"+id, "env-"+id, "agent-1", "openai", "gpt-4o", providerCostCents+1_000, providerCostCents, 10, "USD", "policy-1", "evidence://"+id)
	r.ProviderRequestID = providerRequestID
	r.ProviderPriceSnapshotHash = "sha256:price-" + id
	r.SettlementReceiptHash = "sha256:settle-" + id
	r.LedgerEntryIDs = []string{"ule-" + id}
	r.Reseal()
	if err := r.Validate(); err != nil {
		t.Fatalf("usage receipt %s invalid: %v", id, err)
	}
	return r
}

func invoiceLine(lineID, providerRequestID string, billed int64) ProviderInvoiceLine {
	return ProviderInvoiceLine{LineID: lineID, ProviderRequestID: providerRequestID, ModelID: "gpt-4o", BilledCostCents: billed, Currency: "USD"}
}

func reconWindow() (time.Time, time.Time) {
	end := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	return end.Add(-720 * time.Hour), end
}

// TestReconcile_AllLinesMatch is the happy path: every provider line maps to an
// internal receipt at the same amount, totals agree, status is MATCHED, and each
// line is bound to its internal receipt content hash.
func TestReconcile_AllLinesMatch(t *testing.T) {
	start, end := reconWindow()
	u1 := usageReceiptFor(t, "u1", "prov-req-1", 100)
	u2 := usageReceiptFor(t, "u2", "prov-req-2", 250)

	inv := NewProviderInvoice("inv-1", "openai", "USD", "evidence://inv-1", start, end, []ProviderInvoiceLine{
		invoiceLine("l1", "prov-req-1", 100),
		invoiceLine("l2", "prov-req-2", 250),
	})

	run, err := ReconcileProviderInvoice("run-1", inv, []InternalUsageRecord{UsageReceiptReconView(u1), UsageReceiptReconView(u2)}, "evidence://run-1", end)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if run.Status != ReconStatusMatched {
		t.Fatalf("status = %s, want MATCHED; exceptions=%+v", run.Status, run.Exceptions)
	}
	if !run.IsReconciled() {
		t.Fatalf("expected reconciled run")
	}
	if run.InternalTotalCents != 350 || run.ProviderTotalCents != 350 || run.DeltaCents != 0 {
		t.Fatalf("totals: internal=%d provider=%d delta=%d, want 350/350/0", run.InternalTotalCents, run.ProviderTotalCents, run.DeltaCents)
	}
	if run.MatchedLines != 2 {
		t.Fatalf("matched lines = %d, want 2", run.MatchedLines)
	}
	// Every line must be bound to the internal receipt content hash it matched.
	for _, line := range inv.Lines {
		if line.Status != ProviderLineMatched {
			t.Fatalf("line %s status = %s, want MATCHED", line.LineID, line.Status)
		}
		if line.MatchedReceiptHash == "" {
			t.Fatalf("line %s not bound to an internal receipt hash", line.LineID)
		}
	}
	if inv.Lines[0].MatchedReceiptHash != u1.ContentHash {
		t.Fatalf("line l1 bound to %q, want %q", inv.Lines[0].MatchedReceiptHash, u1.ContentHash)
	}
	if err := run.Validate(); err != nil {
		t.Fatalf("matched run should validate: %v", err)
	}
}

// TestReconcile_MismatchEmitsExceptionAndEvidence is the SPEND6 done-gate: an
// over-billed line and an unmatched line both produce reconciliation exceptions,
// the run is DISCREPANT, and it carries an EvidencePack ref.
func TestReconcile_MismatchEmitsExceptionAndEvidence(t *testing.T) {
	start, end := reconWindow()
	u1 := usageReceiptFor(t, "u1", "prov-req-1", 100) // internal cost 100

	inv := NewProviderInvoice("inv-2", "openai", "USD", "evidence://inv-2", start, end, []ProviderInvoiceLine{
		invoiceLine("l1", "prov-req-1", 130),     // over-billed: 130 vs 100 internal
		invoiceLine("l2", "prov-req-rogue", 500), // no internal receipt at all
	})

	run, err := ReconcileProviderInvoice("run-2", inv, []InternalUsageRecord{UsageReceiptReconView(u1)}, "evidence://run-2", end)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if run.Status != ReconStatusDiscrepant {
		t.Fatalf("status = %s, want DISCREPANT", run.Status)
	}
	if run.IsReconciled() {
		t.Fatalf("discrepant run must not report reconciled")
	}
	// Done gate: exception queue is non-empty and the run references an EvidencePack.
	if len(run.Exceptions) != 2 {
		t.Fatalf("exceptions = %d, want 2: %+v", len(run.Exceptions), run.Exceptions)
	}
	if run.EvidencePackRef == "" {
		t.Fatalf("reconciliation run must carry an EvidencePack ref")
	}

	var sawAmount, sawUnmatched bool
	for _, ex := range run.Exceptions {
		switch ex.Kind {
		case ExceptionAmountMismatch:
			sawAmount = true
			if ex.DeltaCents != 30 {
				t.Fatalf("amount-mismatch delta = %d, want 30", ex.DeltaCents)
			}
			if ex.ReceiptHash != u1.ContentHash {
				t.Fatalf("amount-mismatch exception not bound to internal receipt hash")
			}
		case ExceptionUnmatchedProviderLine:
			sawUnmatched = true
			if ex.ProviderRequestID != "prov-req-rogue" {
				t.Fatalf("unmatched exception request = %s, want prov-req-rogue", ex.ProviderRequestID)
			}
		}
	}
	if !sawAmount || !sawUnmatched {
		t.Fatalf("expected both AMOUNT_MISMATCH and UNMATCHED exceptions; got %+v", run.Exceptions)
	}
	// Delta = provider total (630) - internal total (100) = 530.
	if run.DeltaCents != 530 {
		t.Fatalf("delta = %d, want 530", run.DeltaCents)
	}
	if err := run.Validate(); err != nil {
		t.Fatalf("discrepant run should validate: %v", err)
	}
}

// TestReconcile_MissingProviderLine closes the loop in the other direction: an
// internal receipt the provider never billed for becomes a MISSING_PROVIDER_LINE
// exception so under-billing is also surfaced.
func TestReconcile_MissingProviderLine(t *testing.T) {
	start, end := reconWindow()
	u1 := usageReceiptFor(t, "u1", "prov-req-1", 100)
	u2 := usageReceiptFor(t, "u2", "prov-req-2", 250) // never billed

	inv := NewProviderInvoice("inv-3", "openai", "USD", "evidence://inv-3", start, end, []ProviderInvoiceLine{
		invoiceLine("l1", "prov-req-1", 100),
	})

	run, err := ReconcileProviderInvoice("run-3", inv, []InternalUsageRecord{UsageReceiptReconView(u1), UsageReceiptReconView(u2)}, "evidence://run-3", end)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if run.Status != ReconStatusDiscrepant {
		t.Fatalf("status = %s, want DISCREPANT", run.Status)
	}
	if len(run.Exceptions) != 1 || run.Exceptions[0].Kind != ExceptionMissingProviderLine {
		t.Fatalf("expected one MISSING_PROVIDER_LINE exception, got %+v", run.Exceptions)
	}
	if run.Exceptions[0].ProviderRequestID != "prov-req-2" {
		t.Fatalf("missing exception request = %s, want prov-req-2", run.Exceptions[0].ProviderRequestID)
	}
	// internal total 350, provider total 100, delta -250.
	if run.DeltaCents != -250 {
		t.Fatalf("delta = %d, want -250", run.DeltaCents)
	}
}

// TestReconcile_Deterministic proves the run content hash does not depend on the
// order internal records or invoice lines are supplied in — required so an
// EvidencePack built from the run is offline-reproducible.
func TestReconcile_Deterministic(t *testing.T) {
	start, end := reconWindow()
	u1 := usageReceiptFor(t, "u1", "prov-req-1", 100)
	u2 := usageReceiptFor(t, "u2", "prov-req-2", 250)

	linesA := []ProviderInvoiceLine{invoiceLine("l1", "prov-req-1", 130), invoiceLine("l2", "prov-req-rogue", 500)}
	linesB := []ProviderInvoiceLine{invoiceLine("l2", "prov-req-rogue", 500), invoiceLine("l1", "prov-req-1", 130)}

	invA := NewProviderInvoice("inv-d", "openai", "USD", "evidence://inv-d", start, end, linesA)
	invB := NewProviderInvoice("inv-d", "openai", "USD", "evidence://inv-d", start, end, linesB)

	runA, err := ReconcileProviderInvoice("run-d", invA, []InternalUsageRecord{UsageReceiptReconView(u1), UsageReceiptReconView(u2)}, "evidence://run-d", end)
	if err != nil {
		t.Fatalf("reconcile A: %v", err)
	}
	runB, err := ReconcileProviderInvoice("run-d", invB, []InternalUsageRecord{UsageReceiptReconView(u2), UsageReceiptReconView(u1)}, "evidence://run-d", end)
	if err != nil {
		t.Fatalf("reconcile B: %v", err)
	}
	if runA.ContentHash != runB.ContentHash {
		t.Fatalf("run hash is order-dependent: %s != %s", runA.ContentHash, runB.ContentHash)
	}
}

// TestFreezeDirective_NeverExposesProviderKey is the security invariant: a freeze
// directive built for an agent-visible surface must never carry a provider
// credential, and Validate must reject one that does.
func TestFreezeDirective_NeverExposesProviderKey(t *testing.T) {
	d := NewFreezeDirective("fz-1", FreezeScopeProvider, "tenant-1", FreezeReasonReconciliationMismatch, "sha256:run-2", "evidence://fz-1")
	d.ProviderID = "openai"
	d.Reseal()
	if err := d.Validate(); err != nil {
		t.Fatalf("clean freeze directive should validate: %v", err)
	}
	if d.ExposesProviderKey() {
		t.Fatalf("clean directive must not be flagged as exposing a key")
	}

	// Inject a (synthetic) provider key into a field — Validate must reject it.
	leaked := NewFreezeDirective("fz-2", FreezeScopeProvider, "tenant-1", FreezeReasonPaymentFailure, "sk-live-0123456789abcdef", "evidence://fz-2")
	leaked.ProviderID = "openai"
	leaked.Reseal()
	if !leaked.ExposesProviderKey() {
		t.Fatalf("expected directive carrying an sk- key to be flagged")
	}
	if err := leaked.Validate(); err == nil {
		t.Fatalf("Validate must reject a directive that carries a provider credential")
	}
}

// TestFreezeDirective_ScopeRequiresIdentifiers checks scope/identifier coherence.
func TestFreezeDirective_ScopeRequiresIdentifiers(t *testing.T) {
	// ACCOUNT scope needs an account id.
	acct := NewFreezeDirective("fz-a", FreezeScopeAccount, "tenant-1", FreezeReasonPaymentFailure, "evt-1", "evidence://fz-a")
	if err := acct.Validate(); err == nil {
		t.Fatalf("ACCOUNT scope without account_id must be invalid")
	}
	acct.AccountID = "balance-1"
	acct.Reseal()
	if err := acct.Validate(); err != nil {
		t.Fatalf("ACCOUNT scope with account_id should validate: %v", err)
	}

	// PROVIDER scope needs a provider id.
	prov := NewFreezeDirective("fz-p", FreezeScopeProvider, "tenant-1", FreezeReasonReconciliationMismatch, "sha256:run", "evidence://fz-p")
	if err := prov.Validate(); err == nil {
		t.Fatalf("PROVIDER scope without provider_id must be invalid")
	}
}
