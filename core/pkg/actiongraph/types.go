// Package actiongraph provides signal-to-proposal conversion with dependency graphs.
//
// An ActionProposal groups one or more WorkItems derived from signal clusters
// into a governed unit of work. Each WorkItem may depend on others, forming a
// DAG that DependencyGraph can topologically sort for safe execution ordering.
package actiongraph

import "time"

// ActionProposal is the top-level unit produced by signal-to-action conversion.
// It aggregates work items, risk classification, context, and SLA metadata.
type ActionProposal struct {
	ProposalID  string          `json:"proposal_id"`
	SignalIDs   []string        `json:"signal_ids"`
	ClusterID   string          `json:"cluster_id"`
	AssigneeID  string          `json:"assignee_id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	RiskClass   ActionRiskClass `json:"risk_class"`
	Items       []WorkItem      `json:"items"`
	Context     ContextSlice    `json:"context"`
	SLA         *SLABinding     `json:"sla,omitempty"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	ContentHash string          `json:"content_hash"`
}

// WorkItem is a single unit of work within an ActionProposal.
// Type is one of DRAFT, EFFECT, DECISION, or VERIFY.
type WorkItem struct {
	ItemID        string          `json:"item_id"`
	Type          string          `json:"type"`
	Description   string          `json:"description"`
	EffectType    string          `json:"effect_type,omitempty"`
	Params        map[string]any  `json:"params,omitempty"`
	DependsOn     []string        `json:"depends_on,omitempty"`
	DraftArtifact *DraftArtifact  `json:"draft_artifact,omitempty"`
	RiskClass     ActionRiskClass `json:"risk_class"`
	Status        string          `json:"status"`
}

// DraftArtifact holds a pre-composed content artifact attached to a WorkItem.
// Type is one of email_draft, doc_update, ticket_comment, or chat_message.
type DraftArtifact struct {
	ArtifactID  string `json:"artifact_id"`
	Type        string `json:"type"`
	ContentHash string `json:"content_hash"`
	Content     string `json:"content"`
	URI         string `json:"uri,omitempty"`
}

// ContextSlice provides the surrounding context for an ActionProposal,
// including the signals that triggered it, entity metadata, and policy context.
type ContextSlice struct {
	RelevantSignals []string       `json:"relevant_signals"`
	EntityContext   map[string]any `json:"entity_context,omitempty"`
	PreviousActions []string       `json:"previous_actions,omitempty"`
	PolicyContext   map[string]any `json:"policy_context,omitempty"`
}

// SLABinding attaches a deadline and priority to an ActionProposal.
// Priority ranges from 1 (highest) to 5 (lowest).
type SLABinding struct {
	DeadlineAt time.Time `json:"deadline_at"`
	Priority   int       `json:"priority"`
	Source     string    `json:"source"`
}
