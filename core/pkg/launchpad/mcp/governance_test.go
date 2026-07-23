package mcp

import (
	"testing"
	"time"
)

func scopedServer() ServerRecord {
	return ServerRecord{
		ServerID:           "srv",
		LaunchID:           "launch-1",
		AppID:              "openclaw",
		Principal:          "test.operator",
		PolicyHash:         "sha256:policy",
		Approved:           true,
		credentialVerified: true,
		SchemaPins:         map[string]string{"read": "sha256:read", "write": "sha256:write"},
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

func TestOpaqueApprovedServerRemainsQuarantinedWithoutVerifier(t *testing.T) {
	record := scopedServer()
	record.credentialVerified = false
	decision := Authorize(record, scopedRequest("read", "sha256:read"))
	if decision.Verdict != "ESCALATE" || decision.Reason != "ERR_MCP_APPROVAL_VERIFICATION_UNAVAILABLE" {
		t.Fatalf("opaque approval must fail closed, got %#v", decision)
	}
}

func TestSchemaPinRequired(t *testing.T) {
	record := scopedServer()
	record.SchemaPins = map[string]string{"write": "sha256:abc"}
	req := scopedRequest("write", "sha256:def")
	decision := Authorize(record, req)
	if decision.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", decision.Verdict)
	}
}

func TestSideEffectRequiresApprovalReceipt(t *testing.T) {
	record := scopedServer()
	record.SchemaPins = map[string]string{"write": "sha256:abc"}
	req := scopedRequest("write", "sha256:abc")
	req.Effect = EffectSideEffect
	decision := Authorize(record, req)
	if decision.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", decision.Verdict)
	}
}

func TestRevokeBlocksFutureDispatch(t *testing.T) {
	record := scopedServer()
	record.Revoked = true
	record.SchemaPins = map[string]string{"read": "sha256:abc"}
	req := scopedRequest("read", "sha256:abc")
	decision := Authorize(record, req)
	if decision.Verdict != "DENY" {
		t.Fatalf("expected DENY, got %s", decision.Verdict)
	}
}

func TestLaunchScopedDecisionIncludesLiveAuthorizationFields(t *testing.T) {
	req := scopedRequest("write", "sha256:write")
	req.Effect = EffectSideEffect
	req.ApprovalReceiptRef = "approval-receipt:launch-1/write"

	record := scopedServer()
	record.Approvals = []ApprovalGrant{{
		ReceiptRef: req.ApprovalReceiptRef,
		ToolNames:  []string{"write"},
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	}}
	decision := Authorize(record, req)
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

func TestSideEffectApprovalGrantMustMatchToolAndExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	req := scopedRequest("write", "sha256:write")
	req.Effect = EffectSideEffect
	req.ApprovalReceiptRef = "approval-receipt:launch-1/write"
	record := scopedServer()

	record.Approvals = []ApprovalGrant{{
		ReceiptRef: req.ApprovalReceiptRef,
		ToolNames:  []string{"read"},
		ExpiresAt:  now.Add(time.Hour),
	}}
	if decision := AuthorizeAt(record, req, now); decision.Verdict != "DENY" || decision.Reason != "ERR_MCP_APPROVAL_SCOPE_OR_EXPIRY" {
		t.Fatalf("wrong tool approval should deny, got %#v", decision)
	}

	record.Approvals[0].ToolNames = []string{"write"}
	record.Approvals[0].ExpiresAt = now.Add(-time.Second)
	if decision := AuthorizeAt(record, req, now); decision.Verdict != "DENY" || decision.Reason != "ERR_MCP_APPROVAL_SCOPE_OR_EXPIRY" {
		t.Fatalf("expired approval should deny, got %#v", decision)
	}

	record.Approvals[0].ExpiresAt = now.Add(time.Hour)
	if decision := AuthorizeAt(record, req, now); decision.Verdict != "ALLOW" {
		t.Fatalf("scoped live approval should allow, got %#v", decision)
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

func TestBlankScopeFieldsBlockWildcardAuthorization(t *testing.T) {
	record := scopedServer()
	record.Principal = ""

	decision := Authorize(record, scopedRequest("read", "sha256:read"))
	if decision.Verdict != "DENY" || decision.Reason != "ERR_MCP_LAUNCH_SCOPE_MISMATCH" {
		t.Fatalf("blank record scope should not act as wildcard, got %#v", decision)
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
