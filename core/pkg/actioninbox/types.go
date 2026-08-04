// Package actioninbox provides human governance and approval inbox for
// fail-closed execution control. Every action above a risk threshold must
// be enqueued and approved by one or more human principals before it can
// proceed.
package actioninbox

import (
	"slices"
	"time"
)

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
	// Denial is the structured, model-actionable denial record, present
	// once the item has been denied. Additive (omitempty): older items and
	// non-denied items are unaffected.
	Denial      *DenialRecord `json:"denial,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	ContentHash string        `json:"content_hash"`
}

// SessionContextKey is the InboxItem.Context key carrying the agent session
// identifier. Cascade-reject only propagates within one session.
const SessionContextKey = "session_id"

// SessionID returns the session identifier recorded on the item, or "".
func (i *InboxItem) SessionID() string {
	if i == nil || i.Context == nil {
		return ""
	}
	if s, ok := i.Context[SessionContextKey].(string); ok {
		return s
	}
	return ""
}

// HasApprovalDomain reports whether the item carries the domain-defining
// fields a cascade decision can compare: a requester (EmployeeID) and an
// approval authority (ManagerID). Items lacking them are not comparable —
// fail-closed callers must refuse to cascade to or from them.
func (i *InboxItem) HasApprovalDomain() bool {
	return i != nil && i.EmployeeID != "" && i.ManagerID != ""
}

// SameApprovalDomain reports whether two items belong to the same approval
// domain: identical requester, identical approval authority, and identical
// approval route (who must approve and how). A denial ceremony for one item
// may only cascade within its own domain; denying across managers,
// employees, or routes would let one principal settle asks they are not
// authorized for.
func (i *InboxItem) SameApprovalDomain(other *InboxItem) bool {
	if !i.HasApprovalDomain() || !other.HasApprovalDomain() {
		return false
	}
	if i.EmployeeID != other.EmployeeID || i.ManagerID != other.ManagerID {
		return false
	}
	return i.Route.SameRoute(&other.Route)
}

// SameRoute reports whether two approval routes are identical in every
// field that defines the approval authority and ceremony.
func (r *ApprovalRoute) SameRoute(other *ApprovalRoute) bool {
	if r == nil || other == nil {
		return r == other
	}
	return r.RouteType == other.RouteType &&
		slices.Equal(r.ApproverIDs, other.ApproverIDs) &&
		slices.Equal(r.ApproverRoles, other.ApproverRoles) &&
		r.Quorum == other.Quorum &&
		r.TimeoutSecs == other.TimeoutSecs &&
		r.OnTimeout == other.OnTimeout
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
	CeremonyID     string        `json:"ceremony_id"`
	ItemID         string        `json:"item_id"`
	Route          ApprovalRoute `json:"route"`
	Outcome        string        `json:"outcome"` // APPROVED, DENIED, TIMED_OUT
	StartedAt      time.Time     `json:"started_at"`
	CompletedAt    time.Time     `json:"completed_at"`
	ContentHash    string        `json:"content_hash"`
	ProofGraphNode string        `json:"proof_graph_node"`
}

// EscalationReason records why an item was escalated.
type EscalationReason struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	TriggeredBy string `json:"triggered_by"`
	Urgency     string `json:"urgency"`
}
