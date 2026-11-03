package inferencegateway

import (
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
	TaxBasisCents         int64               `json:"tax_basis_cents"`
	NetBalanceDeltaCents  int64               `json:"net_balance_delta_cents"`
	OpenReservationsCents int64               `json:"open_reservations_cents"`
	EntryCount            int                 `json:"entry_count"`
	GeneratedAt           time.Time           `json:"generated_at"`
}
