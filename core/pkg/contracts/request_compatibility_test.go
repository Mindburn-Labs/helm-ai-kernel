package contracts

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestApprovalReceiptUnmarshalLegacyAliases(t *testing.T) {
	pub := []byte("01234567890123456789012345678901")
	sig := []byte(strings.Repeat("s", 64))
	body := map[string]any{
		"intent_hash":    "sha256:intent",
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"signature_b64":  base64.StdEncoding.EncodeToString(sig),
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	var receipt ApprovalReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if receipt.PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("public key = %q, want %q", receipt.PublicKey, hex.EncodeToString(pub))
	}
	if receipt.Signature != hex.EncodeToString(sig) {
		t.Fatalf("signature = %q, want %q", receipt.Signature, hex.EncodeToString(sig))
	}
}

func TestApprovalReceiptUnmarshalRejectsAliasConflict(t *testing.T) {
	pub := []byte("01234567890123456789012345678901")
	data := []byte(`{"intent_hash":"sha256:intent","public_key":"abcd","public_key_b64":"` + base64.StdEncoding.EncodeToString(pub) + `"}`)
	var receipt ApprovalReceipt
	if err := json.Unmarshal(data, &receipt); err == nil || !strings.Contains(err.Error(), "public_key and public_key_b64 disagree") {
		t.Fatalf("expected public key conflict, got %v", err)
	}
}

func TestBudgetCeilingUnmarshalLegacyAliases(t *testing.T) {
	var ceiling BudgetCeiling
	data := []byte(`{"subject":"tenant:default","window":"24h","max_tool_calls":3,"max_spend_minor":500,"max_egress_bytes":2048,"max_write_ops":7,"approval_required_after":1200}`)
	if err := json.Unmarshal(data, &ceiling); err != nil {
		t.Fatalf("unmarshal budget ceiling: %v", err)
	}
	if ceiling.ToolCallLimit != 3 || ceiling.SpendLimitCents != 500 || ceiling.EgressLimitBytes != 2048 || ceiling.WriteOperationLimit != 7 || ceiling.ApprovalRequiredAbove != 1200 {
		t.Fatalf("legacy aliases did not canonicalize: %+v", ceiling)
	}
}

func TestMCPAuthorizationProfileUnmarshalLegacyAliases(t *testing.T) {
	var profile MCPAuthorizationProfile
	data := []byte(`{"profile_id":"profile-1","required_audience":"mcp://server","protocol_version":"2025-11-25","tool_scopes":{"tool.read":["mcp:tool:read"]}}`)
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("unmarshal MCP profile: %v", err)
	}
	if profile.Resource != "mcp://server" {
		t.Fatalf("resource = %q, want mcp://server", profile.Resource)
	}
	if len(profile.ProtocolVersions) != 1 || profile.ProtocolVersions[0] != "2025-11-25" {
		t.Fatalf("protocol versions = %#v, want singleton legacy version", profile.ProtocolVersions)
	}
	if profile.ToolScopeHash == "" {
		t.Fatal("expected tool scope hash from legacy tool_scopes")
	}
}
