// Package contracts — Design constitution primitives.
//
// Per HELM 2030 Spec §6.1.15:
//
//	HELM OSS MUST include operator-console primitives, information
//	architecture rules, anti-pattern registry, visualization grammar,
//	and agent-facing UI generation constraints.
//
// Resolves: GAP-A26.
package contracts

// ── Anti-Pattern Registry ────────────────────────────────────────

// AntiPatternSeverity classifies how harmful a UI anti-pattern is.
type AntiPatternSeverity string

const (
	APSevWarning  AntiPatternSeverity = "WARNING"
	APSevError    AntiPatternSeverity = "ERROR"
	APSevCritical AntiPatternSeverity = "CRITICAL"
)

// AntiPattern describes a known bad UI/UX pattern that MUST be avoided.
type AntiPattern struct {
	PatternID   string              `json:"pattern_id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Severity    AntiPatternSeverity `json:"severity"`
	Detection   string              `json:"detection"` // CEL expression or rule
	Remediation string              `json:"remediation"`
	Category    string              `json:"category"` // "PARALLEL_TRUTH", "BYPASS", "DARK_PATTERN", "ACCESSIBILITY"
}

// AntiPatternRegistry stores known anti-patterns for validation.
type AntiPatternRegistry interface {
	Register(pattern AntiPattern) error
	Check(surfaceType string, props map[string]any) ([]AntiPattern, error)
	List() ([]AntiPattern, error)
}

// ── Visualization Grammar ────────────────────────────────────────

// VisualizationRule defines how canonical truth should be rendered.
type VisualizationRule struct {
	RuleID      string `json:"rule_id"`
	DataType    string `json:"data_type"` // "PROOFGRAPH", "BUDGET", "DELEGATION", "TIMELINE"
	Rendering   string `json:"rendering"` // "GRAPH", "TABLE", "TIMELINE", "HEATMAP", "TREE"
	Required    bool   `json:"required"`  // MUST be present in conformant UIs
	Constraints string `json:"constraints,omitempty"` // e.g. "no animation on critical data"
}

// ── Agent-Facing UI Constraints ──────────────────────────────────

// AgentUIConstraint restricts what agents can generate for UI surfaces.
type AgentUIConstraint struct {
	ConstraintID string   `json:"constraint_id"`
	Category     string   `json:"category"` // "NO_PARALLEL_TRUTH", "NO_BYPASS", "NO_HIDDEN_STATE"
	Description  string   `json:"description"`
	Enforcement  string   `json:"enforcement"` // "HARD", "SOFT"
	AppliesTo    []string `json:"applies_to"`  // surface types: "CANVAS", "CONSOLE", "REPORT"
}

// ── Console Primitives ───────────────────────────────────────────

// ConsoleTemplate is an operator-console rendering primitive.
type ConsoleTemplate struct {
	TemplateID  string              `json:"template_id"`
	Name        string              `json:"name"`
	SurfaceType string              `json:"surface_type"` // "DASHBOARD", "DETAIL", "LIST", "GRAPH"
	DataSource  string              `json:"data_source"`  // canonical data path
	Layout      string              `json:"layout"`       // "CARD", "TABLE", "SPLIT", "FULL"
	Columns     []ConsoleColumn     `json:"columns,omitempty"`
	Actions     []ConsoleAction     `json:"actions,omitempty"`
}

// ConsoleColumn defines a column in a console view.
type ConsoleColumn struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Sortable  bool   `json:"sortable"`
	Filterable bool  `json:"filterable"`
	Format    string `json:"format,omitempty"` // "DATE", "CURRENCY", "HASH", "STATUS"
}

// ConsoleAction is an action available from a console surface.
type ConsoleAction struct {
	ActionID    string `json:"action_id"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "GOVERNANCE_EVENT", "NAVIGATION", "EXPORT"
	RequiresAuth bool  `json:"requires_auth"`
}

// ── Information Architecture Rules ───────────────────────────────

// InfoArchRule defines structural rules for information layout.
type InfoArchRule struct {
	RuleID      string `json:"rule_id"`
	Scope       string `json:"scope"` // "GLOBAL", "DASHBOARD", "DETAIL", "MODAL"
	Rule        string `json:"rule"`  // e.g. "canonical_data_only", "no_derived_metrics_without_provenance"
	Enforcement string `json:"enforcement"` // "HARD", "SOFT"
}
