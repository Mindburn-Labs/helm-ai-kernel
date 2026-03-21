// Package economic — Vendor.
//
// Per HELM 2030 Spec §5.7:
//
//	Vendor is a first-class governance object representing any external
//	service provider whose costs flow through the treasury.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// VendorRiskTier classifies vendor risk for governance decisions.
type VendorRiskTier string

const (
	VendorRiskLow      VendorRiskTier = "LOW"
	VendorRiskMedium   VendorRiskTier = "MEDIUM"
	VendorRiskHigh     VendorRiskTier = "HIGH"
	VendorRiskCritical VendorRiskTier = "CRITICAL"
)

// VendorStatus tracks vendor lifecycle.
type VendorStatus string

const (
	VendorStatusActive     VendorStatus = "ACTIVE"
	VendorStatusSuspended  VendorStatus = "SUSPENDED"
	VendorStatusTerminated VendorStatus = "TERMINATED"
	VendorStatusPending    VendorStatus = "PENDING_REVIEW"
)

// ContractTerms defines the commercial relationship bounds.
type ContractTerms struct {
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date,omitempty"`
	AutoRenew       bool      `json:"auto_renew"`
	NoticePeriodDays int      `json:"notice_period_days"`
	PaymentSchedule string    `json:"payment_schedule"` // "monthly", "quarterly", "annual", "per_use"
}

// Vendor represents an external service provider under governance.
type Vendor struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Name            string            `json:"name"`
	ServiceType     string            `json:"service_type"`
	RiskTier        VendorRiskTier    `json:"risk_tier"`
	Status          VendorStatus      `json:"status"`
	ContractTerms   ContractTerms     `json:"contract_terms"`
	SpendCapCents   int64             `json:"spend_cap_cents"`
	CurrentSpendCents int64           `json:"current_spend_cents"`
	Currency        string            `json:"currency"`
	Tags            []string          `json:"tags,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	ContentHash     string            `json:"content_hash"`
}

// NewVendor creates a Vendor with deterministic hash.
func NewVendor(id, tenantID, name, serviceType string, riskTier VendorRiskTier, currency string, spendCapCents int64, terms ContractTerms) *Vendor {
	now := time.Now().UTC()
	v := &Vendor{
		ID:            id,
		TenantID:      tenantID,
		Name:          name,
		ServiceType:   serviceType,
		RiskTier:      riskTier,
		Status:        VendorStatusActive,
		ContractTerms: terms,
		SpendCapCents: spendCapCents,
		Currency:      currency,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	v.ContentHash = v.computeHash()
	return v
}

// WithinSpendCap returns true if additional spend would stay within cap.
func (v *Vendor) WithinSpendCap(additionalCents int64) bool {
	if v.SpendCapCents <= 0 {
		return true // no cap
	}
	return v.CurrentSpendCents+additionalCents <= v.SpendCapCents
}

// RecordSpend adds spend and checks cap. Fails closed if cap exceeded.
func (v *Vendor) RecordSpend(amountCents int64) error {
	if !v.WithinSpendCap(amountCents) {
		return errors.New("vendor: spend cap exceeded")
	}
	v.CurrentSpendCents += amountCents
	v.UpdatedAt = time.Now().UTC()
	v.ContentHash = v.computeHash()
	return nil
}

// Suspend transitions the vendor to SUSPENDED status.
func (v *Vendor) Suspend() {
	v.Status = VendorStatusSuspended
	v.UpdatedAt = time.Now().UTC()
	v.ContentHash = v.computeHash()
}

// ContractActive returns true if the contract is within its term.
func (v *Vendor) ContractActive(now time.Time) bool {
	if now.Before(v.ContractTerms.StartDate) {
		return false
	}
	if !v.ContractTerms.EndDate.IsZero() && now.After(v.ContractTerms.EndDate) {
		return false
	}
	return true
}

// Validate ensures the vendor is well-formed.
func (v *Vendor) Validate() error {
	if v.ID == "" {
		return errors.New("vendor: id is required")
	}
	if v.TenantID == "" {
		return errors.New("vendor: tenant_id is required")
	}
	if v.Name == "" {
		return errors.New("vendor: name is required")
	}
	if v.Currency == "" {
		return errors.New("vendor: currency is required")
	}
	if v.RiskTier == "" {
		return errors.New("vendor: risk_tier is required")
	}
	return nil
}

func (v *Vendor) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string         `json:"id"`
		TenantID string         `json:"tenant_id"`
		Name     string         `json:"name"`
		Risk     VendorRiskTier `json:"risk_tier"`
		Status   VendorStatus   `json:"status"`
		SpendCap int64          `json:"spend_cap_cents"`
		Spend    int64          `json:"current_spend_cents"`
	}{v.ID, v.TenantID, v.Name, v.RiskTier, v.Status, v.SpendCapCents, v.CurrentSpendCents})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
