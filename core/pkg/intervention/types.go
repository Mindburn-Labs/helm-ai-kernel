package intervention

import "time"

// ── Intervention Object ────────────────────────────────────────

// InterventionReason classifies why an intervention was triggered.
type InterventionReason string

const (
	ReasonPolicyDeny     InterventionReason = "POLICY_DENY"
	ReasonApprovalNeeded InterventionReason = "APPROVAL_NEEDED"
	ReasonEvidenceGap    InterventionReason = "EVIDENCE_GAP"
	ReasonRiskThreshold  InterventionReason = "RISK_THRESHOLD"
	ReasonManualTrigger  InterventionReason = "MANUAL_TRIGGER"
	ReasonBudgetExceeded InterventionReason = "BUDGET_EXCEEDED"
)

// InterventionState tracks the lifecycle of an intervention.
type InterventionState string

const (
	StatePending  InterventionState = "PENDING"
	StateActive   InterventionState = "ACTIVE"
	StateResolved InterventionState = "RESOLVED"
	StateExpired  InterventionState = "EXPIRED"
	StateCanceled InterventionState = "CANCELED"
)

// InterventionObject represents a request for human intervention.
// It is created when the kernel determines that a human decision is needed
// before execution can proceed.
type InterventionObject struct {
	InterventionID string               `json:"intervention_id"`
	ExecutionID    string               `json:"execution_id"`
	PrincipalID    string               `json:"principal_id"`
	Reason         InterventionReason   `json:"reason"`
	State          InterventionState    `json:"state"`
	Description    string               `json:"description"`
	EffectTypes    []string             `json:"effect_types"`
	PolicyEpoch    string               `json:"policy_epoch"`
	Scope          InterventionScope    `json:"scope"`
	Options        []InterventionOption `json:"options"`
	CreatedAt      time.Time            `json:"created_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	ResolvedAt     *time.Time           `json:"resolved_at,omitempty"`
	ContentHash    string               `json:"content_hash"`
}

// InterventionScope defines what the intervention covers.
type InterventionScope struct {
	TargetResources []string `json:"target_resources,omitempty"`
	TargetActions   []string `json:"target_actions,omitempty"`
	MaxBudget       float64  `json:"max_budget,omitempty"`
	Jurisdiction    string   `json:"jurisdiction,omitempty"`
}

// InterventionOption is a possible resolution for an intervention.
type InterventionOption struct {
	OptionID    string `json:"option_id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Type        string `json:"type"` // "APPROVE", "DENY", "MODIFY", "ESCALATE"
}

// ── Intervention Receipt ───────────────────────────────────────

// InterventionDecision records how the intervention was resolved.
type InterventionDecision string

const (
	DecisionApprove  InterventionDecision = "APPROVE"
	DecisionDeny     InterventionDecision = "DENY"
	DecisionModify   InterventionDecision = "MODIFY"
	DecisionEscalate InterventionDecision = "ESCALATE"
	DecisionCancelOp InterventionDecision = "CANCEL"
)

// InterventionReceipt is the cryptographic proof that a human made
// a governance decision. Every intervention MUST produce a receipt.
type InterventionReceipt struct {
	ReceiptID       string               `json:"receipt_id"`
	InterventionID  string               `json:"intervention_id"`
	DeciderID       string               `json:"decider_id"`
	DeciderType     string               `json:"decider_type"` // "HUMAN", "SYSTEM"
	Decision        InterventionDecision `json:"decision"`
	SelectedOption  string               `json:"selected_option,omitempty"`
	Rationale       string               `json:"rationale,omitempty"`
	Conditions      []string             `json:"conditions,omitempty"`
	PolicyEpoch     string               `json:"policy_epoch"`
	IssuedAt        time.Time            `json:"issued_at"`
	Signature       string               `json:"signature,omitempty"`
	SignerPublicKey string               `json:"signer_public_key,omitempty"`
	ContentHash     string               `json:"content_hash"`
}

// ── Handoff Contract ───────────────────────────────────────────

// HandoffType classifies the kind of delegation.
type HandoffType string

const (
	HandoffHumanToAgent HandoffType = "HUMAN_TO_AGENT"
	HandoffAgentToHuman HandoffType = "AGENT_TO_HUMAN"
	HandoffAgentToAgent HandoffType = "AGENT_TO_AGENT"
)

// HandoffContract defines the terms for delegating execution between principals.
type HandoffContract struct {
	HandoffID      string      `json:"handoff_id"`
	Type           HandoffType `json:"type"`
	FromPrincipal  string      `json:"from_principal"`
	ToPrincipal    string      `json:"to_principal"`
	ScopePolicy    string      `json:"scope_policy"`
	RetainedRights []string    `json:"retained_rights"`
	Conditions     []string    `json:"conditions,omitempty"`
	ExpiresAt      time.Time   `json:"expires_at"`
	CreatedAt      time.Time   `json:"created_at"`
	ContentHash    string      `json:"content_hash"`
	Signature      string      `json:"signature,omitempty"`
}
