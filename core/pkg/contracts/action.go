package contracts

// Action represents a request to perform an operation.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Action struct {
	Type    ActionType     `json:"type"`
	Payload map[string]any `json:"payload"`
}

// ActionType represents the type of action.
type ActionType string

// Action type constants.
const (
	ActionRefundRequest ActionType = "REFUND_REQUEST"
	ActionRefundExecute ActionType = "REFUND_EXECUTE"
	ActionVendorPayment ActionType = "VENDOR_PAYMENT"
	ActionDiscover      ActionType = "DISCOVER"
)

// Actor represents the entity initiating an action.
//
//nolint:govet // fieldalignment: struct layout is human-readable
type Actor struct {
	ID    string            `json:"id"`
	Role  string            `json:"role"` // e.g. "user", "system", "agent"
	Props map[string]string `json:"props,omitempty"`
}

// ActionPlan represents a sequence of steps to achieve a goal.
type ActionPlan struct {
	Steps []WorkflowStep `json:"steps"`
}
