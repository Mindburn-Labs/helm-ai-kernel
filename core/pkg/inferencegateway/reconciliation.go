package inferencegateway

import (
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// Provider reconciliation + freeze path (SPEND6 / MIN-471).
//
// This file wires the canonical economic reconciliation/freeze types onto the
// live SPEND5 BalanceLedger:
//
//   - InternalUsageRecords projects every settled UsageReceipt onto the internal
//     side a provider invoice reconciles against (matched on provider request id
//     and bound to the receipt content hash).
//   - ReconcileProviderInvoice runs the matcher and returns the canonical
//     economic.ProviderReconciliationRun (with the EvidencePack ref and exception
//     queue).
//   - ApplyFreeze flips the account to FROZEN from a FreezeDirective, after which
//     the existing fail-closed paths refuse new spend.
//   - RecordPaymentFailure is the payment-failure path: it freezes/degrades spend
//     authority and is structurally unable to create a negative unmanaged balance
//     (it never debits; a frozen account cannot be debited at all).

// InternalUsageRecords returns the internal reconciliation view of every settled
// usage receipt: one record per committed debit, keyed by provider request id
// and bound to the UsageReceipt content hash. These are exactly the receipt-bound
// debits SPEND5 posted; SPEND6 reconciles a provider invoice against them.
func (l *BalanceLedger) InternalUsageRecords() []economic.InternalUsageRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	records := make([]economic.InternalUsageRecord, 0, len(l.settled))
	for _, rec := range l.settled {
		if rec.UsageReceipt == nil {
			continue
		}
		records = append(records, economic.UsageReceiptReconView(rec.UsageReceipt))
	}
	return records
}

// ReconcileProviderInvoice reconciles a provider invoice against this ledger's
// settled usage and returns the canonical run. The run carries the period,
// internal total, provider total, delta, status, EvidencePack ref, and the
// reconciliation exception queue; every provider line is either matched to an
// internal receipt hash or recorded as an exception.
func (l *BalanceLedger) ReconcileProviderInvoice(runID string, invoice *economic.ProviderInvoice, evidencePackRef string, now time.Time) (*economic.ProviderReconciliationRun, error) {
	return economic.ReconcileProviderInvoice(runID, invoice, l.InternalUsageRecords(), evidencePackRef, now)
}

// ApplyFreeze degrades spend authority for this account by flipping it to FROZEN
// per a validated FreezeDirective. It is idempotent: re-applying a freeze to an
// already-frozen account is a no-op. A FROZEN account refuses every subsequent
// Reserve / debit / credit through the existing fail-closed checks.
//
// The directive carries no provider credentials (enforced by its own Validate),
// so applying it never exposes a provider key.
func (l *BalanceLedger) ApplyFreeze(directive *economic.FreezeDirective) error {
	if err := directive.Validate(); err != nil {
		return fmt.Errorf("inferencegateway: freeze directive invalid: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// Scope must actually target this account/tenant; a provider/tenant-scoped
	// freeze is applied to every account the caller fans it out to, but we still
	// refuse a directive for a different tenant.
	if directive.TenantID != l.account.TenantID {
		return fmt.Errorf("inferencegateway: freeze directive tenant %s does not match account tenant %s", directive.TenantID, l.account.TenantID)
	}
	if directive.Scope == economic.FreezeScopeAccount && directive.AccountID != l.account.ID {
		return fmt.Errorf("inferencegateway: account-scoped freeze targets %s, not this account %s", directive.AccountID, l.account.ID)
	}
	if l.account.Status == economic.BalanceAccountClosed {
		return errors.New("inferencegateway: cannot freeze a closed account")
	}
	l.account.Status = economic.BalanceAccountFrozen
	l.account.UpdatedAt = time.Now().UTC()
	return nil
}

// Frozen reports whether the account is currently frozen.
func (l *BalanceLedger) Frozen() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.account.Status == economic.BalanceAccountFrozen
}

// FreezeOnReconciliation builds and applies a freeze directive when a provider
// reconciliation run is not reconciled. It returns (nil, nil) for a reconciled
// run — a clean reconciliation never freezes. The returned directive references
// the run's content hash as its source evidence.
func (l *BalanceLedger) FreezeOnReconciliation(directiveID string, run *economic.ProviderReconciliationRun, scope economic.FreezeScope, evidencePackRef string) (*economic.FreezeDirective, error) {
	if run == nil {
		return nil, errors.New("inferencegateway: reconciliation run is required")
	}
	if run.IsReconciled() {
		return nil, nil
	}
	directive := economic.NewFreezeDirective(directiveID, scope, l.account.TenantID, economic.FreezeReasonReconciliationMismatch, run.ContentHash, evidencePackRef)
	switch scope {
	case economic.FreezeScopeAccount:
		directive.AccountID = l.account.ID
	case economic.FreezeScopeProvider:
		directive.ProviderID = run.ProviderID
	}
	directive.Reseal()
	if err := l.ApplyFreeze(directive); err != nil {
		return nil, err
	}
	return directive, nil
}

// RecordPaymentFailure is the payment-failure path. A failed provider payment
// must degrade spend authority WITHOUT exposing provider keys and WITHOUT ever
// creating a negative unmanaged balance.
//
// It is structurally safe on the balance: it never debits. It freezes the
// account (so no further debit can occur) and returns the agent-safe freeze
// directive. The balance is left exactly where it was — a payment failure cannot
// push an unmanaged USAGE_BALANCE negative because no negative movement is ever
// posted. For a managed (invoice-accrual) account, the deferred amount is still
// only ever accrued, never cash-debited, so the cash balance still cannot go
// negative through this path.
func (l *BalanceLedger) RecordPaymentFailure(directiveID, paymentEventID, evidencePackRef string, degradeOnly bool) (*economic.FreezeDirective, error) {
	if paymentEventID == "" {
		return nil, errors.New("inferencegateway: payment event id is required")
	}
	directive := economic.NewFreezeDirective(directiveID, economic.FreezeScopeAccount, l.account.TenantID, economic.FreezeReasonPaymentFailure, paymentEventID, evidencePackRef)
	directive.AccountID = l.account.ID
	directive.DegradeOnly = degradeOnly
	directive.Reseal()

	balanceBefore := l.BalanceCents()
	if err := l.ApplyFreeze(directive); err != nil {
		return nil, err
	}
	// Invariant guard: the payment-failure path must not have moved the balance,
	// and certainly must not have driven it negative.
	if after := l.BalanceCents(); after != balanceBefore || after < 0 {
		return nil, fmt.Errorf("inferencegateway: payment-failure path mutated balance (%d -> %d)", balanceBefore, after)
	}
	return directive, nil
}
