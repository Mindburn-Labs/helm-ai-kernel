// Package actioninbox provides human governance and approval inbox for
// fail-closed execution control. Every action above a risk threshold must
// be enqueued and approved by one or more human principals before it can
// proceed.
package actioninbox

import "time"

// InboxItemStatus represents the lifecycle state of an inbox item.
type InboxItemStatus string

const (
	StatusPending      InboxItemStatus = "PENDING"
	StatusApproved     InboxItemStatus = "APPROVED"
	StatusDenied       InboxItemStatus = "DENIED"
	StatusDeferred     InboxItemStatus = "DEFERRED"
	StatusExpired      InboxItemStatus = "EXPIRED"
	StatusAutoApproved InboxItemStatus = "AUTO_APPROVED"
)

// InboxItem represents a single approval request in the governance inbox.
type InboxItem struct {
	ItemID      string            `json:"item_id"`
	ProposalID  string            `json:"proposal_id"`
	EmployeeID  string            `json:"employee_id"`
	ManagerID   string            `json:"manager_id"`
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	RiskClass   string            `json:"risk_class"`
	EffectTypes []string          `json:"effect_types"`
	Context     map[string]any    `json:"context,omitempty"`
	Status      InboxItemStatus   `json:"status"`
	Route       ApprovalRoute     `json:"route"`
	Escalation  *EscalationReason `json:"escalation,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	ContentHash string            `json:"content_hash"`
}

// ApprovalRoute defines how an item must be approved.
type ApprovalRoute struct {
	// RouteType is one of: auto, single_human, dual_control, quorum.
	RouteType     string   `json:"route_type"`
	ApproverIDs   []string `json:"approver_ids,omitempty"`
	ApproverRoles []string `json:"approver_roles,omitempty"`
	Quorum        int      `json:"quorum"`
	TimeoutSecs   int      `json:"timeout_secs"`
	// OnTimeout is one of: deny, escalate, abort.
	OnTimeout string `json:"on_timeout"`
}

// ApprovalCeremonyRecord captures the full audit trail of an approval ceremony.
type ApprovalCeremonyRecord struct {
	CeremonyID    string        `json:"ceremony_id"`
	ItemID        string        `json:"item_id"`
	Route         ApprovalRoute `json:"route"`
	Outcome       string        `json:"outcome"` // APPROVED, DENIED, TIMED_OUT
	StartedAt     time.Time     `json:"started_at"`
	CompletedAt   time.Time     `json:"completed_at"`
	ContentHash   string        `json:"content_hash"`
	ProofGraphNode string       `json:"proof_graph_node"`
}

// EscalationReason records why an item was escalated.
type EscalationReason struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	TriggeredBy string `json:"triggered_by"`
	Urgency     string `json:"urgency"`
}
