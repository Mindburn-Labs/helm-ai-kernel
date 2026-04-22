// Package policybundles implements versioned policy bundle governance for HELM.
// A policy bundle is a collection of governance rules scoped to a jurisdiction
// and use case, with deterministic content hashing for tamper detection.
package policybundles

import "time"

// PolicyBundle is a versioned collection of policy rules for a jurisdiction/use case.
type PolicyBundle struct {
	BundleID    string       `json:"bundle_id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Jurisdiction string      `json:"jurisdiction"` // "US", "EU", "UK", "global"
	Category    string       `json:"category"`     // "retention", "approval", "data_residency", "access_control"
	Version     int          `json:"version"`
	Rules       []PolicyRule `json:"rules"`
	ContentHash string       `json:"content_hash"`
	Status      string       `json:"status"` // "draft", "active", "deprecated"
	CreatedAt   time.Time    `json:"created_at"`
	ActivatedAt *time.Time   `json:"activated_at,omitempty"`
}

// PolicyRule is a single governance rule within a bundle.
type PolicyRule struct {
	RuleID      string            `json:"rule_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Condition   string            `json:"condition"` // CEL expression
	Action      string            `json:"action"`    // "deny", "require_approval", "log", "encrypt"
	Priority    int               `json:"priority"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

// BundleAssignment binds a policy bundle to a tenant/workspace.
type BundleAssignment struct {
	AssignmentID string    `json:"assignment_id"`
	BundleID     string    `json:"bundle_id"`
	TenantID     string    `json:"tenant_id"`
	WorkspaceID  string    `json:"workspace_id,omitempty"` // Empty = tenant-wide
	CreatedAt    time.Time `json:"created_at"`
}

// Status constants.
const (
	BundleStatusDraft      = "draft"
	BundleStatusActive     = "active"
	BundleStatusDeprecated = "deprecated"
)
