// Package tenants implements multi-tenant isolation for HELM enterprise deployments.
// Every principal, resource, and policy evaluation is scoped to a tenant.
// Fail-closed: any error in tenant resolution or isolation check results in denial.
package tenants

import "time"

// Tenant represents an isolated organizational unit in HELM.
type Tenant struct {
	TenantID string            `json:"tenant_id"`
	Name     string            `json:"name"`
	Edition  string            `json:"edition"` // "team", "enterprise", "self-hosted"
	Status   string            `json:"status"`  // "active", "suspended", "deprovisioned"
	OwnerID  string            `json:"owner_id"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// PrincipalIDs lists all principals that belong to this tenant.
	PrincipalIDs []string  `json:"principal_ids,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TenantLimits defines resource boundaries for a tenant.
type TenantLimits struct {
	TenantID          string `json:"tenant_id"`
	MaxWorkspaces     int    `json:"max_workspaces"`
	MaxEmployees      int    `json:"max_employees"`
	MaxConnectors     int    `json:"max_connectors"`
	MaxDailyActions   int    `json:"max_daily_actions"`
	MaxBudgetCentsDay int64  `json:"max_budget_cents_day"`
	MaxStorageBytes   int64  `json:"max_storage_bytes"`
}

// TenantIsolationCheck is the result of a cross-tenant access check.
type TenantIsolationCheck struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	ResourceID  string `json:"resource_id"`
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason"`
}

// Status constants.
const (
	StatusActive        = "active"
	StatusSuspended     = "suspended"
	StatusDeprovisioned = "deprovisioned"
)
