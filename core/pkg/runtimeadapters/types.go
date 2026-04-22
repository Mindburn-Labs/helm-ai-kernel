package runtimeadapters

// AdaptedRequest is a runtime-agnostic representation of a tool call
// that needs to pass through HELM governance.
type AdaptedRequest struct {
	// RuntimeType identifies the source runtime ("mcp", "openclaw", "http").
	RuntimeType string `json:"runtime_type"`

	// ToolName is the name of the tool being called.
	ToolName string `json:"tool_name"`

	// Arguments are the tool call parameters.
	Arguments map[string]any `json:"arguments"`

	// PrincipalID identifies the acting principal (VirtualEmployee or human).
	PrincipalID string `json:"principal_id"`

	// SessionID is the runtime session identifier.
	SessionID string `json:"session_id,omitempty"`

	// DelegationSessionID references an active delegation session.
	DelegationSessionID string `json:"delegation_session_id,omitempty"`

	// Metadata carries runtime-specific metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AdaptedResponse is the governed result of a tool call interception.
type AdaptedResponse struct {
	// Allowed indicates whether the tool call was permitted.
	Allowed bool `json:"allowed"`

	// Result contains the tool execution output (if allowed).
	Result any `json:"result,omitempty"`

	// DenyReason is populated when Allowed is false.
	DenyReason *DenyReason `json:"deny_reason,omitempty"`

	// ReceiptID is the identifier of the execution receipt.
	ReceiptID string `json:"receipt_id"`

	// DecisionID is the identifier of the governance decision.
	DecisionID string `json:"decision_id"`

	// ProofGraphNode is the hash of the ProofGraph node created.
	ProofGraphNode string `json:"proofgraph_node"`
}

// DenyReason explains why a tool call was denied.
type DenyReason struct {
	// Code is the denial reason code (maps to contracts.Reason* constants).
	Code string `json:"code"`

	// Message is a human-readable explanation.
	Message string `json:"message"`

	// Actionable suggests what the caller can do to resolve the denial.
	// Values: "request_approval", "modify_scope", "contact_admin", "increase_budget"
	Actionable string `json:"actionable"`

	// DetailsURI optionally points to more information.
	DetailsURI string `json:"details_uri,omitempty"`
}
