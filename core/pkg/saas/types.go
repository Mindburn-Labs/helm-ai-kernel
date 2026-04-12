// Package saas implements Governance-as-a-Service infrastructure for HELM,
// providing multi-tenant SaaS capabilities including tenant onboarding,
// billing/metering, and isolation auditing.
// Fail-closed: any error in tenant operations results in denial.
package saas

import "time"

// TenantStatus tracks the lifecycle of a SaaS tenant.
type TenantStatus string

const (
	TenantActive      TenantStatus = "ACTIVE"
	TenantSuspended   TenantStatus = "SUSPENDED"
	TenantDeactivated TenantStatus = "DEACTIVATED"
)

// TenantRecord represents a SaaS tenant.
type TenantRecord struct {
	TenantID    string       `json:"tenant_id"`
	OrgName     string       `json:"org_name"`
	Status      TenantStatus `json:"status"`
	Plan        string       `json:"plan"`           // "free", "starter", "enterprise"
	SigningKeyID string      `json:"signing_key_id"` // per-tenant signing key
	CreatedAt   time.Time    `json:"created_at"`
	SuspendedAt time.Time    `json:"suspended_at,omitempty"`
	ContentHash string       `json:"content_hash"`
}

// UsageRecord tracks per-tenant usage for billing.
type UsageRecord struct {
	TenantID        string    `json:"tenant_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	DecisionCount   int64     `json:"decision_count"`
	AllowCount      int64     `json:"allow_count"`
	DenyCount       int64     `json:"deny_count"`
	ReceiptCount    int64     `json:"receipt_count"`
	EvidencePacksGB float64   `json:"evidence_packs_gb"`
	ComputeMillis   int64     `json:"compute_millis"`
}

// BillingEvent is a metered billing event.
type BillingEvent struct {
	EventID   string    `json:"event_id"`
	TenantID  string    `json:"tenant_id"`
	EventType string    `json:"event_type"` // "DECISION", "RECEIPT", "EVIDENCE_PACK", "ZK_PROOF"
	Quantity  int64     `json:"quantity"`
	Timestamp time.Time `json:"timestamp"`
}

// IsolationAuditResult verifies tenant data isolation.
type IsolationAuditResult struct {
	AuditID          string    `json:"audit_id"`
	TenantID         string    `json:"tenant_id"`
	Passed           bool      `json:"passed"`
	CrossTenantLeaks int       `json:"cross_tenant_leaks"` // should be 0
	ResourcesAudited int       `json:"resources_audited"`
	AuditedAt        time.Time `json:"audited_at"`
	ContentHash      string    `json:"content_hash"`
}
