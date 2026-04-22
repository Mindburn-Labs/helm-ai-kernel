// Package contracts — capability_diff.go provides deterministic mapping from
// raw node operations to human-readable capability/control/workflow diffs.
//
// This mapping table is the canonical source for translating low-level
// OpsEvent payloads into user-facing change descriptions. It eliminates
// the need for users to interpret raw ops and replaces them with
// structured, categorized diff summaries.
package contracts

// DiffCategory classifies a capability change.
type DiffCategory string

const (
	DiffCategoryCapability DiffCategory = "CAPABILITY" // New ability gained/lost
	DiffCategoryControl    DiffCategory = "CONTROL"    // Constraint/policy change
	DiffCategoryWorkflow   DiffCategory = "WORKFLOW"   // Process flow change
	DiffCategoryData       DiffCategory = "DATA"       // Data access/schema change
	DiffCategoryBudget     DiffCategory = "BUDGET"     // Cost/resource limit change
	DiffCategoryPosture    DiffCategory = "POSTURE"    // Autonomy level change
)

// DiffSeverity indicates user-attention level for a diff.
type DiffSeverity string

const (
	DiffSeverityInfo     DiffSeverity = "INFO"
	DiffSeverityNotice   DiffSeverity = "NOTICE"
	DiffSeverityWarning  DiffSeverity = "WARNING"
	DiffSeverityCritical DiffSeverity = "CRITICAL"
)

// CapabilityDiff represents a single human-readable change.
type CapabilityDiff struct {
	// ID is a stable, deterministic identifier derived from the source op.
	ID string `json:"id"`

	// Category classifies the change type.
	Category DiffCategory `json:"category"`

	// Severity indicates how much attention this needs.
	Severity DiffSeverity `json:"severity"`

	// Title is a short human-readable summary (max 80 chars).
	Title string `json:"title"`

	// Description is a longer explanation.
	Description string `json:"description,omitempty"`

	// Before/After show the state transition.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`

	// SourceOp is the raw ops event kind that triggered this diff.
	SourceOp string `json:"source_op"`

	// NodeRef is the SmartRef of the affected node (if applicable).
	NodeRef string `json:"node_ref,omitempty"`
}

// OpMapping maps a raw operations event kind to its human-readable diff template.
type OpMapping struct {
	// OpKind is the raw event kind this mapping handles.
	OpKind string

	// Category is the diff category for this op.
	Category DiffCategory

	// DefaultSeverity is the base severity (may be elevated by context).
	DefaultSeverity DiffSeverity

	// TitleTemplate is a Go-template for generating the title.
	// Available variables: .NodeRef, .Principal, .Before, .After
	TitleTemplate string

	// DescriptionTemplate is a Go-template for the description.
	DescriptionTemplate string
}

// DefaultOpMappings is the canonical mapping table from ops → diffs.
// This is the single source of truth for all capability diff translations.
//
//nolint:govet // struct alignment
var DefaultOpMappings = []OpMapping{
	// ── Posture changes ──
	{
		OpKind:              "posture.change",
		Category:            DiffCategoryPosture,
		DefaultSeverity:     DiffSeverityCritical,
		TitleTemplate:       "Autonomy level changed: {{.Before}} → {{.After}}",
		DescriptionTemplate: "The system autonomy level has been updated. This affects what actions can be taken without approval.",
	},

	// ── Budget changes ──
	{
		OpKind:              "budget.update",
		Category:            DiffCategoryBudget,
		DefaultSeverity:     DiffSeverityNotice,
		TitleTemplate:       "Budget updated: {{.After}}",
		DescriptionTemplate: "Resource allocation has been modified.",
	},
	{
		OpKind:              "budget.exhausted",
		Category:            DiffCategoryBudget,
		DefaultSeverity:     DiffSeverityCritical,
		TitleTemplate:       "Budget exhausted",
		DescriptionTemplate: "The allocated budget has been fully consumed. Further operations require budget extension.",
	},

	// ── Capability mutations ──
	{
		OpKind:              "capability.add",
		Category:            DiffCategoryCapability,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "New capability: {{.After}}",
		DescriptionTemplate: "A new capability has been granted to the system.",
	},
	{
		OpKind:              "capability.remove",
		Category:            DiffCategoryCapability,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "Capability removed: {{.Before}}",
		DescriptionTemplate: "A capability has been revoked from the system.",
	},
	{
		OpKind:              "capability.modify",
		Category:            DiffCategoryCapability,
		DefaultSeverity:     DiffSeverityNotice,
		TitleTemplate:       "Capability changed: {{.Before}} → {{.After}}",
		DescriptionTemplate: "An existing capability's parameters have been modified.",
	},

	// ── Control/policy changes ──
	{
		OpKind:              "policy.update",
		Category:            DiffCategoryControl,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "Policy updated: {{.After}}",
		DescriptionTemplate: "A governance policy has been modified. This may affect approval requirements.",
	},
	{
		OpKind:              "corridor.update",
		Category:            DiffCategoryControl,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "Network corridor updated",
		DescriptionTemplate: "Network access boundaries have been modified.",
	},
	{
		OpKind:              "approval.rule.change",
		Category:            DiffCategoryControl,
		DefaultSeverity:     DiffSeverityCritical,
		TitleTemplate:       "Approval rule changed: {{.After}}",
		DescriptionTemplate: "Approval requirements have been modified. This affects which operations need human authorization.",
	},

	// ── Workflow changes ──
	{
		OpKind:              "workflow.add",
		Category:            DiffCategoryWorkflow,
		DefaultSeverity:     DiffSeverityNotice,
		TitleTemplate:       "New workflow: {{.After}}",
		DescriptionTemplate: "A new workflow has been registered.",
	},
	{
		OpKind:              "workflow.modify",
		Category:            DiffCategoryWorkflow,
		DefaultSeverity:     DiffSeverityNotice,
		TitleTemplate:       "Workflow modified: {{.After}}",
		DescriptionTemplate: "An existing workflow's steps have been changed.",
	},
	{
		OpKind:              "workflow.remove",
		Category:            DiffCategoryWorkflow,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "Workflow removed: {{.Before}}",
		DescriptionTemplate: "A workflow has been deregistered.",
	},

	// ── Data access changes ──
	{
		OpKind:              "data.access.grant",
		Category:            DiffCategoryData,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "Data access granted: {{.After}}",
		DescriptionTemplate: "New data access permissions have been granted.",
	},
	{
		OpKind:              "data.access.revoke",
		Category:            DiffCategoryData,
		DefaultSeverity:     DiffSeverityNotice,
		TitleTemplate:       "Data access revoked: {{.Before}}",
		DescriptionTemplate: "Data access permissions have been revoked.",
	},
	{
		OpKind:              "connector.add",
		Category:            DiffCategoryData,
		DefaultSeverity:     DiffSeverityNotice,
		TitleTemplate:       "Connector added: {{.After}}",
		DescriptionTemplate: "A new external connector has been registered.",
	},
	{
		OpKind:              "connector.remove",
		Category:            DiffCategoryData,
		DefaultSeverity:     DiffSeverityWarning,
		TitleTemplate:       "Connector removed: {{.Before}}",
		DescriptionTemplate: "An external connector has been deregistered.",
	},
}

// OpMappingIndex builds a lookup index from OpKind → OpMapping.
func OpMappingIndex() map[string]*OpMapping {
	index := make(map[string]*OpMapping, len(DefaultOpMappings))
	for i := range DefaultOpMappings {
		index[DefaultOpMappings[i].OpKind] = &DefaultOpMappings[i]
	}
	return index
}
