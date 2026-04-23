package auth

import "time"

// Tenant represents a strict isolation boundary.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"` // ACTIVE, SUSPENDED
}

// User represents an authenticated entity within a tenant.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	TenantID  string    `json:"tenant_id"`
	Roles     []string  `json:"roles"` // e.g., "admin", "viewer"
	CreatedAt time.Time `json:"created_at"`
}

// Principal is the interface for any entity making a request (User, ServiceAccount, System).
type Principal interface {
	GetID() string
	GetTenantID() string
	GetRoles() []string
	// HasPermission checks if the principal has a specific permission.
	// This might be delegated to the PolicyEngine, but the Principal carries the roles.
	HasPermission(perm string) bool
}

// BasePrincipal is a simple implementation of Principal.
type BasePrincipal struct {
	ID       string
	TenantID string
	Roles    []string
}

func (b *BasePrincipal) GetID() string {
	return b.ID
}

func (b *BasePrincipal) GetTenantID() string {
	return b.TenantID
}

func (b *BasePrincipal) GetRoles() []string {
	return b.Roles
}

func (b *BasePrincipal) HasPermission(perm string) bool {
	// Simple check: admins have everything
	for _, role := range b.Roles {
		if role == "admin" {
			return true
		}
	}
	return false
}
