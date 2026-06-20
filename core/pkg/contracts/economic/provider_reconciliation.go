package economic

// Provider reconciliation (SPEND6 / MIN-471).
//
// SPEND5 established the internal side of the loop: every metered usage debit is
// evidenced by a UsageReceipt + balanced SettlementReceipt, every non-usage
// balance movement by a BalanceMovementReceipt, and the immutable UsageLedger
// rolls up into a FinanceExport whose net equals the account's cash movement.
//
// SPEND6 closes the loop against the *provider* side. A provider periodically
// bills HELM (a ProviderInvoice with one ProviderInvoiceLine per charge). Each
// line must reconcile to an internal UsageReceipt — matched on the provider
// request id and the internal receipt's content hash — or it enters a
// reconciliation exception. The run aggregates internal total, provider total,
// and delta into a typed status, references its EvidencePack, and (per policy)
// can emit a FreezeDirective that degrades spend authority for the affected
// provider/account/tenant without ever exposing provider keys.
//
// This file only adds reconciliation machinery over the existing canonical
// types; it does not define a parallel proof universe. The internal totals it
// reconciles against are the same receipt-bound entries SPEND5 already posts,
// and the run reuses the SPEND5 ReconciliationStatus vocabulary.

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// ProviderInvoiceLineStatus is the per-line reconciliation outcome.
type ProviderInvoiceLineStatus string

const (
	// ProviderLinePending is the initial state before matching runs.
	ProviderLinePending ProviderInvoiceLineStatus = "PENDING"
	// ProviderLineMatched means the line matched an internal receipt exactly.
	ProviderLineMatched ProviderInvoiceLineStatus = "MATCHED"
	// ProviderLineAmountMismatch means a receipt was found for the provider
	// request id but the billed amount differs from the internal provider cost.
	ProviderLineAmountMismatch ProviderInvoiceLineStatus = "AMOUNT_MISMATCH"
	// ProviderLineUnmatched means no internal receipt exists for the line at all
	// (a charge HELM has no usage record for).
	ProviderLineUnmatched ProviderInvoiceLineStatus = "UNMATCHED"
)

// ProviderInvoiceLine is one billed charge on a provider invoice. BilledCostCents
// is what the provider billed; the line reconciles against the internal
// UsageReceipt whose ProviderRequestID matches and whose content hash the
// matcher binds into MatchedReceiptHash on success.
type ProviderInvoiceLine struct {
	LineID            string `json:"line_id"`
	ProviderRequestID string `json:"provider_request_id"`
	ModelID           string `json:"model_id"`
	BilledCostCents   int64  `json:"billed_cost_cents"`
	Currency          string `json:"currency"`
	// MatchedReceiptHash is the internal UsageReceipt content hash this line
	// reconciled to. Empty until a successful match.
	MatchedReceiptHash string                    `json:"matched_receipt_hash,omitempty"`
	Status             ProviderInvoiceLineStatus `json:"status"`
}

// Validate ensures a provider invoice line is well-formed before matching.
func (l ProviderInvoiceLine) Validate() error {
	if l.LineID == "" {
		return errors.New("provider_invoice_line: line_id is required")
	}
	if l.ProviderRequestID == "" {
		return errors.New("provider_invoice_line: provider_request_id is required")
	}
	if l.BilledCostCents < 0 {
		return errors.New("provider_invoice_line: billed_cost_cents cannot be negative")
	}
	if l.Currency == "" {
		return errors.New("provider_invoice_line: currency is required")
	}
	return nil
}

// ProviderInvoice is a provider's bill for a billing period. It is the external
// counterpart of the internal UsageLedger: reconciliation matches every line to
// an internal UsageReceipt or files an exception.
type ProviderInvoice struct {
	ID              string                `json:"id"`
	ProviderID      string                `json:"provider_id"`
	TenantID        string                `json:"tenant_id,omitempty"`
	Currency        string                `json:"currency"`
	PeriodStart     time.Time             `json:"period_start"`
	PeriodEnd       time.Time             `json:"period_end"`
	Lines           []ProviderInvoiceLine `json:"lines"`
	EvidencePackRef string                `json:"evidence_pack_ref"`
	ContentHash     string                `json:"content_hash"`
}

// NewProviderInvoice builds a provider invoice with a deterministic hash. Lines
// start PENDING; matching transitions them.
func NewProviderInvoice(id, providerID, currency, evidencePackRef string, periodStart, periodEnd time.Time, lines []ProviderInvoiceLine) *ProviderInvoice {
	normalized := make([]ProviderInvoiceLine, len(lines))
	copy(normalized, lines)
	for i := range normalized {
		if normalized[i].Status == "" {
			normalized[i].Status = ProviderLinePending
		}
		if normalized[i].Currency == "" {
			normalized[i].Currency = currency
		}
	}
	inv := &ProviderInvoice{
		ID:              id,
		ProviderID:      providerID,
		Currency:        currency,
		PeriodStart:     periodStart,
		PeriodEnd:       periodEnd,
		Lines:           normalized,
		EvidencePackRef: evidencePackRef,
	}
	inv.ContentHash = inv.computeHash()
	return inv
}

// TotalBilledCents sums all billed line amounts.
func (inv *ProviderInvoice) TotalBilledCents() int64 {
	var total int64
	for _, l := range inv.Lines {
		total += l.BilledCostCents
	}
	return total
}

// Validate ensures the invoice can be reconciled.
func (inv *ProviderInvoice) Validate() error {
	if inv == nil {
		return errors.New("provider_invoice: invoice is nil")
	}
	if inv.ID == "" {
		return errors.New("provider_invoice: id is required")
	}
	if inv.ProviderID == "" {
		return errors.New("provider_invoice: provider_id is required")
	}
	if inv.Currency == "" {
		return errors.New("provider_invoice: currency is required")
	}
	if !inv.PeriodEnd.After(inv.PeriodStart) {
		return errors.New("provider_invoice: period_end must be after period_start")
	}
	if inv.EvidencePackRef == "" {
		return errors.New("provider_invoice: evidence_pack_ref is required")
	}
	if len(inv.Lines) == 0 {
		return errors.New("provider_invoice: at least one line is required")
	}
	seen := make(map[string]struct{}, len(inv.Lines))
	for _, l := range inv.Lines {
		if err := l.Validate(); err != nil {
			return err
		}
		if l.Currency != inv.Currency {
			return fmt.Errorf("provider_invoice: line %s currency %s does not match invoice currency %s", l.LineID, l.Currency, inv.Currency)
		}
		if _, dup := seen[l.LineID]; dup {
			return fmt.Errorf("provider_invoice: duplicate line_id %s", l.LineID)
		}
		seen[l.LineID] = struct{}{}
	}
	return nil
}

func (inv *ProviderInvoice) computeHash() string {
	type lineDigest struct {
		LineID            string `json:"line_id"`
		ProviderRequestID string `json:"provider_request_id"`
		BilledCostCents   int64  `json:"billed_cost_cents"`
	}
	digests := make([]lineDigest, len(inv.Lines))
	for i, l := range inv.Lines {
		digests[i] = lineDigest{l.LineID, l.ProviderRequestID, l.BilledCostCents}
	}
	return hashSpendAuthorityCanonical(struct {
		ID         string       `json:"id"`
		ProviderID string       `json:"provider_id"`
		TenantID   string       `json:"tenant_id,omitempty"`
		Currency   string       `json:"currency"`
		Total      int64        `json:"total_billed_cents"`
		Lines      []lineDigest `json:"lines"`
	}{inv.ID, inv.ProviderID, inv.TenantID, inv.Currency, inv.TotalBilledCents(), digests})
}

// InternalUsageRecord is the minimal internal-side view a reconciliation needs:
// the provider request id the provider also billed under, the internal provider
// cost for that request, and the content hash of the UsageReceipt that evidences
// it. It is produced from SPEND5 UsageReceipts (see UsageReceiptReconView).
type InternalUsageRecord struct {
	ProviderRequestID string
	ProviderCostCents int64
	ReceiptHash       string
}

// UsageReceiptReconView projects a SPEND5 UsageReceipt onto the internal record
// a provider reconciliation matches against. It binds the receipt's content hash
// so a matched provider line is provably tied to internal evidence.
func UsageReceiptReconView(r *UsageReceipt) InternalUsageRecord {
	if r == nil {
		return InternalUsageRecord{}
	}
	return InternalUsageRecord{
		ProviderRequestID: r.ProviderRequestID,
		ProviderCostCents: r.ProviderCostCents,
		ReceiptHash:       r.ContentHash,
	}
}

// ReconciliationExceptionKind classifies why a provider line failed to reconcile.
type ReconciliationExceptionKind string

const (
	// ExceptionUnmatchedProviderLine: provider billed for a request HELM has no
	// internal usage receipt for.
	ExceptionUnmatchedProviderLine ReconciliationExceptionKind = "UNMATCHED_PROVIDER_LINE"
	// ExceptionAmountMismatch: a receipt exists but the billed amount differs from
	// the internal provider cost.
	ExceptionAmountMismatch ReconciliationExceptionKind = "AMOUNT_MISMATCH"
	// ExceptionMissingProviderLine: HELM has an internal usage receipt the provider
	// never billed for (internal-only; possible under-billing or a dropped charge).
	ExceptionMissingProviderLine ReconciliationExceptionKind = "MISSING_PROVIDER_LINE"
)

// ReconciliationException is one unreconciled item queued for governance review.
// It is append-only evidence; resolution happens through an approved correction
// (BalanceMovementCorrection), never by editing the exception.
type ReconciliationException struct {
	Kind              ReconciliationExceptionKind `json:"kind"`
	LineID            string                      `json:"line_id,omitempty"`
	ProviderRequestID string                      `json:"provider_request_id"`
	BilledCostCents   int64                       `json:"billed_cost_cents"`
	InternalCostCents int64                       `json:"internal_cost_cents"`
	DeltaCents        int64                       `json:"delta_cents"`
	ReceiptHash       string                      `json:"receipt_hash,omitempty"`
}

// ProviderReconciliationRun is the canonical SPEND6 reconciliation artifact for
// one provider invoice. It records period, internal total, provider total, the
// signed delta, a typed status, the EvidencePack ref, and the exception queue.
//
// It reuses (does not duplicate) the SPEND5 ReconciliationStatus vocabulary:
// MATCHED when every line reconciles and totals agree, DISCREPANT when any
// exception exists, ESCALATED/RESOLVED through the same lifecycle transitions.
type ProviderReconciliationRun struct {
	ID                 string                    `json:"id"`
	ProviderID         string                    `json:"provider_id"`
	TenantID           string                    `json:"tenant_id,omitempty"`
	ProviderInvoiceID  string                    `json:"provider_invoice_id"`
	Currency           string                    `json:"currency"`
	PeriodStart        time.Time                 `json:"period_start"`
	PeriodEnd          time.Time                 `json:"period_end"`
	InternalTotalCents int64                     `json:"internal_total_cents"`
	ProviderTotalCents int64                     `json:"provider_total_cents"`
	DeltaCents         int64                     `json:"delta_cents"`
	MatchedLines       int                       `json:"matched_lines"`
	Status             ReconciliationStatus      `json:"status"`
	Exceptions         []ReconciliationException `json:"exceptions,omitempty"`
	EvidencePackRef    string                    `json:"evidence_pack_ref"`
	CreatedAt          time.Time                 `json:"created_at"`
	ContentHash        string                    `json:"content_hash"`
}

// IsReconciled reports whether every line reconciled and totals agree.
func (run *ProviderReconciliationRun) IsReconciled() bool {
	return run != nil && len(run.Exceptions) == 0 && run.DeltaCents == 0
}

// Validate ensures the run is well-formed and internally consistent.
func (run *ProviderReconciliationRun) Validate() error {
	if run == nil {
		return errors.New("provider_reconciliation_run: run is nil")
	}
	if run.ID == "" {
		return errors.New("provider_reconciliation_run: id is required")
	}
	if run.ProviderID == "" {
		return errors.New("provider_reconciliation_run: provider_id is required")
	}
	if run.ProviderInvoiceID == "" {
		return errors.New("provider_reconciliation_run: provider_invoice_id is required")
	}
	if run.Currency == "" {
		return errors.New("provider_reconciliation_run: currency is required")
	}
	if run.EvidencePackRef == "" {
		return errors.New("provider_reconciliation_run: evidence_pack_ref is required")
	}
	if run.Status == "" {
		return errors.New("provider_reconciliation_run: status is required")
	}
	// Invariant: a reconciled run carries no exceptions and a zero delta; a
	// non-reconciled run must be DISCREPANT/ESCALATED and carry exceptions.
	switch run.Status {
	case ReconStatusMatched:
		if len(run.Exceptions) != 0 || run.DeltaCents != 0 {
			return errors.New("provider_reconciliation_run: MATCHED run cannot have exceptions or a non-zero delta")
		}
	case ReconStatusDiscrepant, ReconStatusEscalated:
		if len(run.Exceptions) == 0 {
			return errors.New("provider_reconciliation_run: DISCREPANT/ESCALATED run must carry at least one exception")
		}
	}
	return nil
}

func (run *ProviderReconciliationRun) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID             string               `json:"id"`
		ProviderID     string               `json:"provider_id"`
		InvoiceID      string               `json:"provider_invoice_id"`
		InternalTotal  int64                `json:"internal_total_cents"`
		ProviderTotal  int64                `json:"provider_total_cents"`
		Delta          int64                `json:"delta_cents"`
		MatchedLines   int                  `json:"matched_lines"`
		Status         ReconciliationStatus `json:"status"`
		ExceptionCount int                  `json:"exception_count"`
	}{run.ID, run.ProviderID, run.ProviderInvoiceID, run.InternalTotalCents, run.ProviderTotalCents, run.DeltaCents, run.MatchedLines, run.Status, len(run.Exceptions)})
}

// ReconcileProviderInvoice matches every provider invoice line against the
// supplied internal usage records and produces a ProviderReconciliationRun.
//
// Matching rule (per acceptance criteria — "provider invoice line matching
// against internal receipt hashes"):
//
//   - A line MATCHES when an internal record shares its provider request id AND
//     the billed amount equals the internal provider cost; the internal receipt
//     hash is bound into the line and (via the exception/match set) the run.
//   - A line with a matching request id but a different amount is an
//     AMOUNT_MISMATCH exception.
//   - A line with no matching internal record is an UNMATCHED_PROVIDER_LINE
//     exception.
//   - An internal record never billed by the provider is a MISSING_PROVIDER_LINE
//     exception (internal-only), so the loop is closed in both directions.
//
// The invoice's line statuses are updated in place. The run's totals are the
// internal provider-cost total and the provider billed total; the delta is
// provider - internal. Determinism: exceptions are emitted in a stable order so
// the run's content hash (and any EvidencePack built from it) is reproducible.
func ReconcileProviderInvoice(runID string, invoice *ProviderInvoice, internal []InternalUsageRecord, evidencePackRef string, now time.Time) (*ProviderReconciliationRun, error) {
	if err := invoice.Validate(); err != nil {
		return nil, err
	}
	if evidencePackRef == "" {
		return nil, errors.New("provider_reconciliation_run: evidence_pack_ref is required")
	}

	byRequest := make(map[string]InternalUsageRecord, len(internal))
	var internalTotal int64
	for _, rec := range internal {
		if rec.ProviderRequestID == "" {
			return nil, errors.New("provider_reconciliation_run: internal record missing provider_request_id")
		}
		if rec.ReceiptHash == "" {
			return nil, errors.New("provider_reconciliation_run: internal record missing receipt_hash")
		}
		if _, dup := byRequest[rec.ProviderRequestID]; dup {
			return nil, fmt.Errorf("provider_reconciliation_run: duplicate internal record for provider_request_id %s", rec.ProviderRequestID)
		}
		byRequest[rec.ProviderRequestID] = rec
		internalTotal += rec.ProviderCostCents
	}

	var exceptions []ReconciliationException
	billedRequests := make(map[string]struct{}, len(invoice.Lines))
	matched := 0

	for i := range invoice.Lines {
		line := &invoice.Lines[i]
		billedRequests[line.ProviderRequestID] = struct{}{}
		rec, ok := byRequest[line.ProviderRequestID]
		if !ok {
			line.Status = ProviderLineUnmatched
			line.MatchedReceiptHash = ""
			exceptions = append(exceptions, ReconciliationException{
				Kind:              ExceptionUnmatchedProviderLine,
				LineID:            line.LineID,
				ProviderRequestID: line.ProviderRequestID,
				BilledCostCents:   line.BilledCostCents,
				DeltaCents:        line.BilledCostCents,
			})
			continue
		}
		if line.BilledCostCents != rec.ProviderCostCents {
			line.Status = ProviderLineAmountMismatch
			line.MatchedReceiptHash = rec.ReceiptHash
			exceptions = append(exceptions, ReconciliationException{
				Kind:              ExceptionAmountMismatch,
				LineID:            line.LineID,
				ProviderRequestID: line.ProviderRequestID,
				BilledCostCents:   line.BilledCostCents,
				InternalCostCents: rec.ProviderCostCents,
				DeltaCents:        line.BilledCostCents - rec.ProviderCostCents,
				ReceiptHash:       rec.ReceiptHash,
			})
			continue
		}
		line.Status = ProviderLineMatched
		line.MatchedReceiptHash = rec.ReceiptHash
		matched++
	}

	// Internal-only records the provider never billed — close the loop both ways.
	for _, rec := range internal {
		if _, billed := billedRequests[rec.ProviderRequestID]; billed {
			continue
		}
		exceptions = append(exceptions, ReconciliationException{
			Kind:              ExceptionMissingProviderLine,
			ProviderRequestID: rec.ProviderRequestID,
			InternalCostCents: rec.ProviderCostCents,
			DeltaCents:        -rec.ProviderCostCents,
			ReceiptHash:       rec.ReceiptHash,
		})
	}

	sortExceptions(exceptions)

	providerTotal := invoice.TotalBilledCents()
	run := &ProviderReconciliationRun{
		ID:                 runID,
		ProviderID:         invoice.ProviderID,
		TenantID:           invoice.TenantID,
		ProviderInvoiceID:  invoice.ID,
		Currency:           invoice.Currency,
		PeriodStart:        invoice.PeriodStart,
		PeriodEnd:          invoice.PeriodEnd,
		InternalTotalCents: internalTotal,
		ProviderTotalCents: providerTotal,
		DeltaCents:         providerTotal - internalTotal,
		MatchedLines:       matched,
		EvidencePackRef:    evidencePackRef,
		CreatedAt:          now.UTC(),
		Exceptions:         exceptions,
	}
	if len(exceptions) == 0 && run.DeltaCents == 0 {
		run.Status = ReconStatusMatched
	} else {
		run.Status = ReconStatusDiscrepant
	}
	run.ContentHash = run.computeHash()
	return run, nil
}

// sortExceptions orders exceptions deterministically (kind, then request id, then
// line id) so a run's content hash is reproducible regardless of input ordering.
func sortExceptions(ex []ReconciliationException) {
	sort.SliceStable(ex, func(i, j int) bool {
		if ex[i].Kind != ex[j].Kind {
			return ex[i].Kind < ex[j].Kind
		}
		if ex[i].ProviderRequestID != ex[j].ProviderRequestID {
			return ex[i].ProviderRequestID < ex[j].ProviderRequestID
		}
		return ex[i].LineID < ex[j].LineID
	})
}
