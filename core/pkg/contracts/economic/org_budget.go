// Package economic — OrgBudget.
//
// Per HELM 2030 Spec §5.7:
//
//	Organizational budgets define spending authority hierarchies.
//	OrgBudget extends the core budget/types.go with organizational semantics
//	(departments, cost centers, approval thresholds).
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// BudgetScope defines what the budget covers.
type BudgetScope string

const (
	BudgetScopeOrg        BudgetScope = "ORGANIZATION"
	BudgetScopeDepartment BudgetScope = "DEPARTMENT"
	BudgetScopeTeam       BudgetScope = "TEAM"
	BudgetScopeProject    BudgetScope = "PROJECT"
	BudgetScopeAgent      BudgetScope = "AGENT"
)

// ApprovalThreshold defines when human approval is required.
type ApprovalThreshold struct {
	AmountCents int64  `json:"amount_cents"`
	ApproverRole string `json:"approver_role"`
}

// OrgBudget is an organizational budget with hierarchical authority.
type OrgBudget struct {
	ID                 string              `json:"id"`
	TenantID           string              `json:"tenant_id"`
	Name               string              `json:"name"`
	Scope              BudgetScope         `json:"scope"`
	ScopeID            string              `json:"scope_id"` // department ID, team ID, etc.
	ParentBudgetID     string              `json:"parent_budget_id,omitempty"`
	AllocatedCents     int64               `json:"allocated_cents"`
	SpentCents         int64               `json:"spent_cents"`
	ReservedCents      int64               `json:"reserved_cents"`
	Currency           string              `json:"currency"`
	PeriodStart        time.Time           `json:"period_start"`
	PeriodEnd          time.Time           `json:"period_end"`
	ApprovalThresholds []ApprovalThreshold `json:"approval_thresholds"`
	Metadata           map[string]string   `json:"metadata,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
	ContentHash        string              `json:"content_hash"`
}

// NewOrgBudget creates an organizational budget.
func NewOrgBudget(id, tenantID, name string, scope BudgetScope, scopeID, currency string, allocatedCents int64, periodStart, periodEnd time.Time) *OrgBudget {
	now := time.Now().UTC()
	ob := &OrgBudget{
		ID:             id,
		TenantID:       tenantID,
		Name:           name,
		Scope:          scope,
		ScopeID:        scopeID,
		AllocatedCents: allocatedCents,
		Currency:       currency,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	ob.ContentHash = ob.computeHash()
	return ob
}

// RemainingCents returns unspent and unreserved budget.
func (ob *OrgBudget) RemainingCents() int64 {
	remaining := ob.AllocatedCents - ob.SpentCents - ob.ReservedCents
	if remaining < 0 {
		return 0
	}
	return remaining
}

// UtilizationPct returns the percentage of budget used (0.0 – 1.0).
func (ob *OrgBudget) UtilizationPct() float64 {
	if ob.AllocatedCents == 0 {
		return 0
	}
	return float64(ob.SpentCents) / float64(ob.AllocatedCents)
}

// CanSpend checks if the budget allows a given spend. Fails closed.
func (ob *OrgBudget) CanSpend(amountCents int64) bool {
	return ob.RemainingCents() >= amountCents
}

// RequiredApprover returns the role that must approve a spend of this amount.
// Returns empty string if no approval threshold applies.
func (ob *OrgBudget) RequiredApprover(amountCents int64) string {
	var bestRole string
	var bestThreshold int64
	for _, t := range ob.ApprovalThresholds {
		if amountCents >= t.AmountCents && t.AmountCents >= bestThreshold {
			bestRole = t.ApproverRole
			bestThreshold = t.AmountCents
		}
	}
	return bestRole
}

// RecordSpend records an actual spend against the budget.
func (ob *OrgBudget) RecordSpend(amountCents int64) error {
	if !ob.CanSpend(amountCents) {
		return errors.New("org_budget: insufficient remaining budget")
	}
	ob.SpentCents += amountCents
	ob.UpdatedAt = time.Now().UTC()
	ob.ContentHash = ob.computeHash()
	return nil
}

// Validate ensures the budget is well-formed.
func (ob *OrgBudget) Validate() error {
	if ob.ID == "" {
		return errors.New("org_budget: id is required")
	}
	if ob.TenantID == "" {
		return errors.New("org_budget: tenant_id is required")
	}
	if ob.AllocatedCents <= 0 {
		return errors.New("org_budget: allocated_cents must be positive")
	}
	if ob.Currency == "" {
		return errors.New("org_budget: currency is required")
	}
	if ob.PeriodEnd.Before(ob.PeriodStart) {
		return errors.New("org_budget: period_end must be after period_start")
	}
	return nil
}

func (ob *OrgBudget) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID        string      `json:"id"`
		TenantID  string      `json:"tenant_id"`
		Scope     BudgetScope `json:"scope"`
		Allocated int64       `json:"allocated"`
		Spent     int64       `json:"spent"`
		Reserved  int64       `json:"reserved"`
	}{ob.ID, ob.TenantID, ob.Scope, ob.AllocatedCents, ob.SpentCents, ob.ReservedCents})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
