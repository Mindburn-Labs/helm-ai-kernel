package mcp

import (
	"encoding/json"
	"fmt"
)

// ElicitationRequest is sent by the server when a tool call requires
// additional information or approval from the user/client.
// Only emitted on the modern /mcp transport; legacy /mcp/v1/* uses
// direct deny/error responses instead.
type ElicitationRequest struct {
	Message         string `json:"message"`
	RequestedSchema any    `json:"requestedSchema,omitempty"` // JSON Schema for expected input
	Action          string `json:"action,omitempty"`          // "approve" | "provide_input"
}

// ElicitationResponse is the client's reply to an elicitation request.
type ElicitationResponse struct {
	Action string         `json:"action"`           // "accept" | "reject" | "provide"
	Data   map[string]any `json:"data,omitempty"`   // Fields matching requestedSchema
	Reason string         `json:"reason,omitempty"` // Optional rejection reason
}

// ElicitationNotification is a JSON-RPC notification sent from server to
// client when a tool call triggers an ESCALATE verdict or requires input.
type ElicitationNotification struct {
	JSONRPC string              `json:"jsonrpc"`
	Method  string              `json:"method"` // "elicitation/create"
	Params  ElicitationNParams  `json:"params"`
}

// ElicitationNParams wraps the elicitation payload.
type ElicitationNParams struct {
	RequestID string             `json:"requestId"` // Correlates to the original tools/call id
	Request   ElicitationRequest `json:"request"`
}

// MarshalElicitationNotification creates a JSON-RPC notification for elicitation.
func MarshalElicitationNotification(requestID string, req ElicitationRequest) ([]byte, error) {
	notification := ElicitationNotification{
		JSONRPC: "2.0",
		Method:  "elicitation/create",
		Params: ElicitationNParams{
			RequestID: fmt.Sprintf("%v", requestID),
			Request:   req,
		},
	}
	return json.Marshal(notification)
}

// IsElicitationVerdictStr returns true if the verdict string indicates
// the request should trigger an elicitation flow (ESCALATE or PENDING).
func IsElicitationVerdict(verdict string) bool {
	switch verdict {
	case "ESCALATE", "PENDING":
		return true
	default:
		return false
	}
}
