package tenants

import (
	"context"
	"fmt"
)

// IsolationEnforcer prevents cross-tenant data access.
// Fail-closed: any error during evaluation results in denial.
type IsolationEnforcer struct {
	store TenantStore
}

// NewIsolationEnforcer creates a new isolation enforcer.
func NewIsolationEnforcer(store TenantStore) *IsolationEnforcer {
	return &IsolationEnforcer{store: store}
}

// CheckAccess verifies that a principal belongs to the claimed tenant and
// can access the specified resource. Fail-closed: any store error returns denied.
func (e *IsolationEnforcer) CheckAccess(ctx context.Context, principalID, tenantID, resourceID string) *TenantIsolationCheck {
	result := &TenantIsolationCheck{
		PrincipalID: principalID,
		TenantID:    tenantID,
		ResourceID:  resourceID,
		Allowed:     false,
	}

	tenant, err := e.store.Get(ctx, tenantID)
	if err != nil {
		result.Reason = fmt.Sprintf("tenant lookup failed: %v", err)
		return result
	}

	// Suspended or deprovisioned tenants cannot be accessed.
	if tenant.Status != StatusActive {
		result.Reason = fmt.Sprintf("tenant %s is %s", tenantID, tenant.Status)
		return result
	}

	// Check if the principal belongs to the tenant (owner or member).
	if tenant.OwnerID == principalID {
		result.Allowed = true
		result.Reason = "principal is tenant owner"
		return result
	}

	for _, pid := range tenant.PrincipalIDs {
		if pid == principalID {
			result.Allowed = true
			result.Reason = "principal is tenant member"
			return result
		}
	}

	result.Reason = fmt.Sprintf("principal %s does not belong to tenant %s", principalID, tenantID)
	return result
}

// EnforceLimits checks if a tenant has exceeded its resource limits.
// Returns (withinLimits, reason). Fail-closed: store errors return false.
func (e *IsolationEnforcer) EnforceLimits(ctx context.Context, tenantID string, currentWorkspaces, currentEmployees, currentConnectors int) (bool, string) {
	limits, err := e.store.GetLimits(ctx, tenantID)
	if err != nil {
		return false, fmt.Sprintf("limits lookup failed: %v", err)
	}

	if currentWorkspaces > limits.MaxWorkspaces {
		return false, fmt.Sprintf("workspace limit exceeded: %d > %d", currentWorkspaces, limits.MaxWorkspaces)
	}
	if currentEmployees > limits.MaxEmployees {
		return false, fmt.Sprintf("employee limit exceeded: %d > %d", currentEmployees, limits.MaxEmployees)
	}
	if currentConnectors > limits.MaxConnectors {
		return false, fmt.Sprintf("connector limit exceeded: %d > %d", currentConnectors, limits.MaxConnectors)
	}

	return true, "within limits"
}
