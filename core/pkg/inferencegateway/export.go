package inferencegateway

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// FinanceExportLine is one typed roll-up row in a finance export.
type FinanceExportLine struct {
	EntryType   economic.UsageLedgerEntryType `json:"entry_type"`
	Direction   economic.SettlementDirection  `json:"direction"`
	EntryCount  int                           `json:"entry_count"`
	AmountCents int64                         `json:"amount_cents"`
}

// FinanceExport is a deterministic roll-up of every posted ledger entry, grouped
// by entry type and direction. It is the finance-facing view that must reconcile
// against the live balance: the net of all balance-affecting entries equals the
// account's movement from its opening balance.
//
// RESERVE/RELEASE entries are hold movements, not balance movements, so they are
// reported (for auditability) but excluded from NetBalanceDeltaCents. Accruals
// are bookkeeping-only and also do not move the cash balance.
type FinanceExport struct {
	TenantID              string              `json:"tenant_id"`
	BalanceAccountID      string              `json:"balance_account_id"`
	Currency              string              `json:"currency"`
	Lines                 []FinanceExportLine `json:"lines"`
	TotalCreditsCents     int64               `json:"total_credits_cents"`
	TotalDebitsCents      int64               `json:"total_debits_cents"`
	ProviderCostCents     int64               `json:"provider_cost_cents"`
	PlatformFeeCents      int64               `json:"platform_fee_cents"`
	InvoiceAccruedCents   int64               `json:"invoice_accrued_cents"`
	NetBalanceDeltaCents  int64               `json:"net_balance_delta_cents"`
	OpenReservationsCents int64               `json:"open_reservations_cents"`
	EntryCount            int                 `json:"entry_count"`
	GeneratedAt           time.Time           `json:"generated_at"`
}

// FinanceExport produces the finance roll-up from the immutable ledger entries.
// Provider-cost and platform-fee accrual totals come from the dedicated accrual
// roll-ups so a reconciliation can prove the debit invariant (debit == provider
// cost + platform fee) at the aggregate level.
func (l *BalanceLedger) FinanceExport() FinanceExport {
	l.mu.Lock()
	defer l.mu.Unlock()

	type key struct {
		t economic.UsageLedgerEntryType
		d economic.SettlementDirection
	}
	grouped := make(map[key]*FinanceExportLine)
	order := make([]key, 0)
	var credits, debits, openHolds int64

	for _, e := range l.entries {
		k := key{e.Type, e.Direction}
		line, ok := grouped[k]
		if !ok {
			line = &FinanceExportLine{EntryType: e.Type, Direction: e.Direction}
			grouped[k] = line
			order = append(order, k)
		}
		line.EntryCount++
		line.AmountCents += e.AmountCents

		// RESERVE/RELEASE are hold movements; accrual entries are bookkeeping.
		// Only true balance movements (DEBIT/CREDIT/ADJUSTMENT that touched the
		// cash balance) net into the balance delta.
		// RESERVE/RELEASE are hold movements; accrual entries are bookkeeping.
		// Only true balance movements net into the cash balance delta.
		if _, isAccrual := l.accrualEntryIDs[e.ID]; isAccrual {
			continue
		}
		switch e.Type {
		case economic.UsageLedgerReserve, economic.UsageLedgerRelease:
			// hold movement only
		default: // DEBIT, CREDIT, ADJUSTMENT
			if e.Direction == economic.SettlementCredit {
				credits += e.AmountCents
			} else {
				debits += e.AmountCents
			}
		}
	}

	for _, res := range l.reservations {
		if !res.Released && !res.Consumed {
			openHolds += res.AmountCents
		}
	}

	lines := make([]FinanceExportLine, 0, len(order))
	for _, k := range order {
		lines = append(lines, *grouped[k])
	}

	return FinanceExport{
		TenantID:              l.account.TenantID,
		BalanceAccountID:      l.account.ID,
		Currency:              l.account.Currency,
		Lines:                 lines,
		TotalCreditsCents:     credits,
		TotalDebitsCents:      debits,
		ProviderCostCents:     l.providerCostAccruedCents,
		PlatformFeeCents:      l.platformFeeAccruedCents,
		InvoiceAccruedCents:   l.invoiceAccruedCents,
		NetBalanceDeltaCents:  credits - debits,
		OpenReservationsCents: openHolds,
		EntryCount:            len(l.entries),
		GeneratedAt:           time.Now().UTC(),
	}
}

// Reconciles reports whether the export's net balance delta equals the account's
// actual movement from its opening balance, producing a canonical
// economic.ReconciliationRecord as the audit artifact. openingBalanceCents is
// the balance the account was created with.
func (l *BalanceLedger) Reconciles(openingBalanceCents int64, periodStart, periodEnd time.Time, treasuryID string) (*economic.ReconciliationRecord, bool) {
	export := l.FinanceExport()
	l.mu.Lock()
	current := l.account.BalanceCents
	l.mu.Unlock()

	expectedDelta := current - openingBalanceCents
	actualDelta := export.NetBalanceDeltaCents

	rec := economic.NewReconciliationRecord(
		fmt.Sprintf("recon-%s", export.BalanceAccountID),
		export.TenantID, treasuryID, periodStart, periodEnd,
		expectedDelta, actualDelta,
	)
	return rec, rec.IsBalanced()
}
