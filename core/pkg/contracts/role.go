// Package contracts — Role schema.
//
// Per HELM 2030 Spec §5.1:
//
//	Roles are first-class governance objects with typed taxonomies.
//	Every actor in a HELM-governed org has a canonical role binding.
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// RoleTaxonomy classifies roles in the governance hierarchy.
type RoleTaxonomy string

const (
	RoleOwner    RoleTaxonomy = "OWNER"
	RoleAdmin    RoleTaxonomy = "ADMIN"
	RoleOperator RoleTaxonomy = "OPERATOR"
	RoleAuditor  RoleTaxonomy = "AUDITOR"
	RoleAgent    RoleTaxonomy = "AGENT"
	RoleService  RoleTaxonomy = "SERVICE"
	RoleObserver RoleTaxonomy = "OBSERVER"
	RoleCustom   RoleTaxonomy = "CUSTOM"
)

// RoleNamespace groups roles by domain.
type RoleNamespace string

const (
	RoleNSGlobal     RoleNamespace = "global"
	RoleNSGovernance RoleNamespace = "governance"
	RoleNSExecution  RoleNamespace = "execution"
	RoleNSEconomic   RoleNamespace = "economic"
	RoleNSSecurity   RoleNamespace = "security"
)

// PermissionScope defines the boundary of a permission grant.
type PermissionScope struct {
	Resource  string `json:"resource"`            // resource type
	Action    string `json:"action"`              // e.g. "read", "write", "execute", "approve"
	Condition string `json:"condition,omitempty"` // optional CEL expression
}

// Role is the canonical role schema for HELM governance.
type Role struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Taxonomy    RoleTaxonomy      `json:"taxonomy"`
	Namespace   RoleNamespace     `json:"namespace"`
	Description string            `json:"description"`
	Permissions []PermissionScope `json:"permissions"`
	MaxActors   int               `json:"max_actors,omitempty"` // 0 = unlimited
	Inherits    []string          `json:"inherits,omitempty"`   // parent role IDs
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ContentHash string            `json:"content_hash"`
}

// NewRole creates a canonical role.
func NewRole(id, tenantID, name string, taxonomy RoleTaxonomy, namespace RoleNamespace, permissions []PermissionScope) *Role {
	r := &Role{
		ID:          id,
		TenantID:    tenantID,
		Name:        name,
		Taxonomy:    taxonomy,
		Namespace:   namespace,
		Permissions: permissions,
		CreatedAt:   time.Now().UTC(),
	}
	r.ContentHash = r.computeHash()
	return r
}

// HasPermission checks if this role grants a specific permission.
func (r *Role) HasPermission(resource, action string) bool {
	for _, p := range r.Permissions {
		if (p.Resource == resource || p.Resource == "*") && (p.Action == action || p.Action == "*") {
			return true
		}
	}
	return false
}

// Validate ensures the role is well-formed.
func (r *Role) Validate() error {
	if r.ID == "" {
		return errors.New("role: id is required")
	}
	if r.TenantID == "" {
		return errors.New("role: tenant_id is required")
	}
	if r.Name == "" {
		return errors.New("role: name is required")
	}
	if r.Taxonomy == "" {
		return errors.New("role: taxonomy is required")
	}
	return nil
}

func (r *Role) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string       `json:"id"`
		TenantID string       `json:"tenant_id"`
		Name     string       `json:"name"`
		Taxonomy RoleTaxonomy `json:"taxonomy"`
		Perms    int          `json:"perm_count"`
	}{r.ID, r.TenantID, r.Name, r.Taxonomy, len(r.Permissions)})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
