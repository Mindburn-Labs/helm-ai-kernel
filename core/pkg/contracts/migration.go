// Package contracts — Schema migration and forward migration rules.
//
// Per HELM 2030 Spec §5.1:
//
//	HELM MUST include forward migration rules for schema versioning.
//
// Resolves: GAP-A2.
package contracts

import "time"

// MigrationRule defines a forward migration from one schema version to another.
type MigrationRule struct {
	RuleID       string    `json:"rule_id"`
	SchemaName   string    `json:"schema_name"`
	FromVersion  string    `json:"from_version"`
	ToVersion    string    `json:"to_version"`
	Description  string    `json:"description"`
	Reversible   bool      `json:"reversible"`
	Transform    string    `json:"transform"` // CEL expression or migration script path
	Validation   string    `json:"validation,omitempty"` // CEL expression to validate post-migration
	CreatedAt    time.Time `json:"created_at"`
}

// MigrationPlan is an ordered list of migration rules to apply.
type MigrationPlan struct {
	PlanID     string          `json:"plan_id"`
	SchemaName string          `json:"schema_name"`
	From       string          `json:"from_version"`
	To         string          `json:"to_version"`
	Steps      []MigrationRule `json:"steps"`
}

// MigrationRegistry stores available migration rules.
type MigrationRegistry interface {
	Register(rule MigrationRule) error
	Lookup(schemaName, from, to string) (*MigrationPlan, error)
	ListVersions(schemaName string) ([]string, error)
}
