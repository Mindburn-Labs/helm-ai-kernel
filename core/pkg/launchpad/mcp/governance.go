package mcp

import "strings"

type ToolEffect string

const (
	EffectRead       ToolEffect = "read"
	EffectSideEffect ToolEffect = "side_effect"
)

type ServerRecord struct {
	ServerID     string            `json:"server_id"`
	LaunchID     string            `json:"launch_id"`
	AppID        string            `json:"app_id"`
	Principal    string            `json:"principal"`
	PolicyHash   string            `json:"policy_hash"`
	Approved     bool              `json:"approved"`
	Revoked      bool              `json:"revoked"`
	RevokedTools map[string]bool   `json:"revoked_tools,omitempty"`
	SchemaPins   map[string]string `json:"schema_pins"`
	ApprovalRefs []string          `json:"approval_refs"`
}

type CallRequest struct {
	ServerID           string     `json:"server_id"`
	LaunchID           string     `json:"launch_id"`
	AppID              string     `json:"app_id"`
	Principal          string     `json:"principal"`
	PolicyHash         string     `json:"policy_hash"`
	ToolName           string     `json:"tool_name"`
	SchemaHash         string     `json:"schema_hash"`
	ApprovalReceiptRef string     `json:"approval_receipt_ref,omitempty"`
	Effect             ToolEffect `json:"effect"`
}

type Decision struct {
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason"`
	LaunchID   string `json:"launch_id,omitempty"`
	AppID      string `json:"app_id,omitempty"`
	Principal  string `json:"principal,omitempty"`
	PolicyHash string `json:"policy_hash,omitempty"`
	SchemaPin  string `json:"schema_pin,omitempty"`
}

func Authorize(record ServerRecord, req CallRequest) Decision {
	decision := Decision{
		LaunchID:   req.LaunchID,
		AppID:      req.AppID,
		Principal:  req.Principal,
		PolicyHash: req.PolicyHash,
	}
	if record.ServerID == "" || record.ServerID != req.ServerID {
		decision.Verdict = "ESCALATE"
		decision.Reason = "ERR_MCP_SERVER_QUARANTINED"
		return decision
	}
	if !sameScope(record.LaunchID, req.LaunchID) || !sameScope(record.AppID, req.AppID) || !sameScope(record.Principal, req.Principal) || !sameScope(record.PolicyHash, req.PolicyHash) {
		decision.Verdict = "DENY"
		decision.Reason = "ERR_MCP_LAUNCH_SCOPE_MISMATCH"
		return decision
	}
	if record.Revoked {
		decision.Verdict = "DENY"
		decision.Reason = "ERR_MCP_SERVER_REVOKED"
		return decision
	}
	if !record.Approved {
		decision.Verdict = "ESCALATE"
		decision.Reason = "ERR_MCP_SERVER_QUARANTINED"
		return decision
	}
	if record.RevokedTools[req.ToolName] {
		decision.Verdict = "DENY"
		decision.Reason = "ERR_MCP_TOOL_REVOKED"
		return decision
	}
	pinned, ok := record.SchemaPins[req.ToolName]
	decision.SchemaPin = pinned
	if !ok {
		decision.Verdict = "ESCALATE"
		decision.Reason = "ERR_MCP_TOOL_QUARANTINED"
		return decision
	}
	if pinned == "" || req.SchemaHash == "" || pinned != req.SchemaHash {
		decision.Verdict = "DENY"
		decision.Reason = "ERR_MCP_SCHEMA_DRIFT"
		return decision
	}
	if req.Effect == EffectSideEffect && req.ApprovalReceiptRef == "" {
		decision.Verdict = "DENY"
		decision.Reason = "ERR_MCP_APPROVAL_RECEIPT_REQUIRED"
		return decision
	}
	decision.Verdict = "ALLOW"
	decision.Reason = "MCP_CALL_AUTHORIZED"
	return decision
}

func sameScope(recordValue, requestValue string) bool {
	return strings.TrimSpace(recordValue) != "" && recordValue == requestValue
}
