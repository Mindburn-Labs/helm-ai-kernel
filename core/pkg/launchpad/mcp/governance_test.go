package mcp

import "testing"

func scopedServer() ServerRecord {
	return ServerRecord{
		ServerID:   "srv",
		LaunchID:   "launch-1",
		AppID:      "openclaw",
		Principal:  "test.operator",
		PolicyHash: "sha256:policy",
		Approved:   true,
		SchemaPins: map[string]string{"read": "sha256:read", "write": "sha256:write"},
	}
}

func scopedRequest(toolName, schemaHash string) CallRequest {
	return CallRequest{
		ServerID:   "srv",
		LaunchID:   "launch-1",
		AppID:      "openclaw",
		Principal:  "test.operator",
		PolicyHash: "sha256:policy",
		ToolName:   toolName,
		SchemaHash: schemaHash,
	}
}

func TestUnknownServerQuarantines(t *testing.T) {
	decision := Authorize(ServerRecord{}, CallRequest{ServerID: "unknown", ToolName: "write"})
	if decision.Verdict != "ESCALATE" {
		t.Fatalf("expected ESCALATE, got %s", decision.Verdict)
	}
}

func TestSchemaPinRequired(t *testing.T) {
	record := ServerRecord{ServerID: "srv", Approved: true, SchemaPins: map[string]string{"write": "sha256:abc"}}
	decision := Authorize(record, CallRequest{ServerID: "srv", ToolName: "write", SchemaHash: "sha256:def"})
	if decision.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", decision.Verdict)
	}
}

func TestSideEffectRequiresApprovalReceipt(t *testing.T) {
	record := ServerRecord{ServerID: "srv", Approved: true, SchemaPins: map[string]string{"write": "sha256:abc"}}
	decision := Authorize(record, CallRequest{ServerID: "srv", ToolName: "write", SchemaHash: "sha256:abc", Effect: EffectSideEffect})
	if decision.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", decision.Verdict)
	}
}

func TestRevokeBlocksFutureDispatch(t *testing.T) {
	record := ServerRecord{ServerID: "srv", Approved: true, Revoked: true, SchemaPins: map[string]string{"read": "sha256:abc"}}
	decision := Authorize(record, CallRequest{ServerID: "srv", ToolName: "read", SchemaHash: "sha256:abc"})
	if decision.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", decision.Verdict)
	}
}

func TestLaunchScopedDecisionIncludesLiveAuthorizationFields(t *testing.T) {
	req := scopedRequest("write", "sha256:write")
	req.Effect = EffectSideEffect
	req.ApprovalReceiptRef = "approval-receipt:launch-1/write"

	decision := Authorize(scopedServer(), req)
	if decision.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %#v", decision)
	}
	if decision.LaunchID != req.LaunchID || decision.AppID != req.AppID || decision.Principal != req.Principal || decision.PolicyHash != req.PolicyHash {
		t.Fatalf("decision lost launch scope: %#v", decision)
	}
	if decision.SchemaPin != "sha256:write" {
		t.Fatalf("decision schema pin = %q", decision.SchemaPin)
	}
}

func TestLaunchScopeMismatchBlocks(t *testing.T) {
	req := scopedRequest("read", "sha256:read")
	req.PolicyHash = "sha256:other-policy"

	decision := Authorize(scopedServer(), req)
	if decision.Verdict != "DENY" || decision.Reason != "ERR_MCP_LAUNCH_SCOPE_MISMATCH" {
		t.Fatalf("launch scope mismatch should deny, got %#v", decision)
	}
}

func TestUnknownToolQuarantines(t *testing.T) {
	decision := Authorize(scopedServer(), scopedRequest("shell.exec", "sha256:shell"))
	if decision.Verdict != "ESCALATE" || decision.Reason != "ERR_MCP_TOOL_QUARANTINED" {
		t.Fatalf("unknown tool should quarantine, got %#v", decision)
	}
}

func TestSchemaDriftBlocks(t *testing.T) {
	decision := Authorize(scopedServer(), scopedRequest("read", "sha256:drift"))
	if decision.Verdict != "DENY" || decision.Reason != "ERR_MCP_SCHEMA_DRIFT" {
		t.Fatalf("schema drift should deny, got %#v", decision)
	}
}

func TestRevokedToolBlocks(t *testing.T) {
	record := scopedServer()
	record.RevokedTools = map[string]bool{"write": true}

	decision := Authorize(record, scopedRequest("write", "sha256:write"))
	if decision.Verdict != "DENY" || decision.Reason != "ERR_MCP_TOOL_REVOKED" {
		t.Fatalf("revoked tool should deny, got %#v", decision)
	}
}
