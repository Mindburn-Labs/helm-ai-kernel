package contracts

import (
	"encoding/json"
	"testing"
)

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
