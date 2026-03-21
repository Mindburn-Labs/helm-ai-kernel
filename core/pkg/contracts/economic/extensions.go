// Package economic — Extended economic primitives.
//
// Per HELM 2030 Spec §5.7:
//
//	Recurring authority models, capital allocation rules, and internal
//	service charging primitives MUST be first-class policy entities.
//
// Resolves: GAP-A15, GAP-A16, GAP-A17.
package economic

import "time"

// ── GAP-A15: Recurring Authority ─────────────────────────────────

// RecurringAuthority is a standing spend authorization that repeats.
type RecurringAuthority struct {
	AuthorityID    string        `json:"authority_id"`
	GrantedTo      string        `json:"granted_to"`     // principal
	GrantedBy      string        `json:"granted_by"`     // authorizer
	Purpose        string        `json:"purpose"`
	MaxAmountCents int64         `json:"max_amount_cents"` // per period
	Currency       string        `json:"currency"`
	Period         string        `json:"period"` // "DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "ANNUAL"
	AutoRenew      bool          `json:"auto_renew"`
	StartDate      time.Time     `json:"start_date"`
	EndDate        *time.Time    `json:"end_date,omitempty"`
	UsedThisPeriod int64         `json:"used_this_period_cents"`
	PeriodStart    time.Time     `json:"period_start"`
	ApprovalChain  []string      `json:"approval_chain,omitempty"`
	Active         bool          `json:"active"`
}

// Remaining returns cents remaining in the current period.
func (r *RecurringAuthority) Remaining() int64 {
	rem := r.MaxAmountCents - r.UsedThisPeriod
	if rem < 0 {
		return 0
	}
	return rem
}

// CanSpend checks if a spend within this period is authorized.
func (r *RecurringAuthority) CanSpend(amountCents int64) bool {
	return r.Active && amountCents <= r.Remaining()
}

// ── GAP-A16: Capital Allocation ──────────────────────────────────

// AllocationStrategy defines how capital is distributed.
type AllocationStrategy string

const (
	AllocProportional AllocationStrategy = "PROPORTIONAL"
	AllocFixed        AllocationStrategy = "FIXED"
	AllocPriority     AllocationStrategy = "PRIORITY"
	AllocDemandDriven AllocationStrategy = "DEMAND_DRIVEN"
)

// CapitalAllocation distributes budget across organizational units.
type CapitalAllocation struct {
	AllocationID   string             `json:"allocation_id"`
	SourceBudgetID string             `json:"source_budget_id"`
	TotalCents     int64              `json:"total_cents"`
	Currency       string             `json:"currency"`
	Strategy       AllocationStrategy `json:"strategy"`
	Allocations    []UnitAllocation   `json:"allocations"`
	FiscalPeriod   string             `json:"fiscal_period"` // e.g. "2026-Q1"
	ApprovedBy     string             `json:"approved_by"`
	ApprovedAt     time.Time          `json:"approved_at"`
}

// UnitAllocation is a single allocation to an organizational unit.
type UnitAllocation struct {
	UnitID     string  `json:"unit_id"`
	UnitName   string  `json:"unit_name"`
	AmountCents int64  `json:"amount_cents"`
	Percentage float64 `json:"percentage,omitempty"` // for proportional
	Priority   int     `json:"priority,omitempty"`   // for priority-based
}

// ── GAP-A17: Internal Service Charging ───────────────────────────

// ChargeType distinguishes chargeback from showback.
type ChargeType string

const (
	ChargeChargeback ChargeType = "CHARGEBACK" // actual budget transfer
	ChargeShowback   ChargeType = "SHOWBACK"   // visibility only
)

// ServiceChargeRecord records internal charging between org units.
type ServiceChargeRecord struct {
	ChargeID       string     `json:"charge_id"`
	Type           ChargeType `json:"type"`
	ProviderUnit   string     `json:"provider_unit"`   // who provides the service
	ConsumerUnit   string     `json:"consumer_unit"`   // who consumes
	ServiceName    string     `json:"service_name"`
	AmountCents    int64      `json:"amount_cents"`
	Currency       string     `json:"currency"`
	Quantity       float64    `json:"quantity"`
	Unit           string     `json:"unit"` // "API_CALL", "COMPUTE_HOUR", "TOKEN", "GB"
	RatePerUnit    float64    `json:"rate_per_unit"`
	Period         string     `json:"period"` // billing period
	CreatedAt      time.Time  `json:"created_at"`
	Settled        bool       `json:"settled"`
	SettledAt      *time.Time `json:"settled_at,omitempty"`
}
