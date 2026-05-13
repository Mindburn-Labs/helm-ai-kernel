// Package rbac implements role-based access control for HELM AI Enterprise deployments.
// Permissions are scoped to tenants and optionally to workspaces or programs.
// Fail-closed: any error during permission evaluation results in denial.
package rbac

import "time"

// Role defines a named set of permissions.
type Role struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	TenantID    string    `json:"tenant_id"`
	Permissions []string  `json:"permissions"` // e.g. "workspace:read", "employee:manage", "inbox:approve"
	IsBuiltin   bool      `json:"is_builtin"`
	CreatedAt   time.Time `json:"created_at"`
}

// RoleBinding assigns a role to a principal within a scope.
type RoleBinding struct {
	BindingID   string     `json:"binding_id"`
	PrincipalID string     `json:"principal_id"`
	RoleID      string     `json:"role_id"`
	TenantID    string     `json:"tenant_id"`
	Scope       string     `json:"scope"` // "tenant", "workspace:{id}", "program:{id}"
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// AccessDecision is the result of a permission check.
type AccessDecision struct {
	Allowed    bool   `json:"allowed"`
	Permission string `json:"permission"`
	RoleID     string `json:"role_id,omitempty"`
	Reason     string `json:"reason"`
}
