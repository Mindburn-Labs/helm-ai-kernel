package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestExecutionFirewallFiltersToolsByQuarantineAndScope(t *testing.T) {
	ctx := context.Background()
	catalog := NewToolCatalog()
	tools := []ToolRef{
		{Name: "read", ServerID: "srv-1"},
		{Name: "write", ServerID: "srv-1", RequiredScopes: []string{"tools.write"}},
	}
	registry := NewQuarantineRegistry()
	firewall := NewExecutionFirewall(catalog, registry, "epoch-42")
	firewall.Clock = boundaryFixedClock()

	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-1"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if _, err := firewall.FilterVisibleTools(ctx, "srv-1", tools, []string{"tools.write"}); err == nil {
		t.Fatal("quarantined server should fail list-time visibility")
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	visible, err := firewall.FilterVisibleTools(ctx, "srv-1", tools, nil)
	if err != nil {
		t.Fatalf("filter tools: %v", err)
	}
	if len(visible) != 1 || visible[0].Name != "read" {
		t.Fatalf("visible tools = %#v, want only read", visible)
	}
}

func TestExecutionFirewallDeniesUnknownToolBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-1",
		ToolName: "missing",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny {
		t.Fatalf("verdict = %s, want DENY", record.Verdict)
	}
	if record.ReasonCode != contracts.ReasonSchemaViolation {
		t.Fatalf("reason = %s, want schema violation", record.ReasonCode)
	}
	if record.RecordHash == "" {
		t.Fatal("deny record was not sealed")
	}
}

func TestExecutionFirewallDeniesUnknownServerBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	catalog := NewToolCatalog()
	tool := ToolRef{Name: "local.echo", ServerID: "srv-unknown", Schema: map[string]any{"type": "object"}}
	if err := catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	firewall := NewExecutionFirewall(catalog, NewQuarantineRegistry(), "epoch-42")
	firewall.Clock = boundaryFixedClock()
	hash, err := ToolSchemaHash(tool)
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:         "srv-unknown",
		ToolName:         "local.echo",
		ArgsHash:         "sha256:args",
		PinnedSchemaHash: hash,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny {
		t.Fatalf("verdict = %s, want DENY", record.Verdict)
	}
	if record.ReasonCode != contracts.ReasonApprovalRequired {
		t.Fatalf("reason = %s, want approval required", record.ReasonCode)
	}
}

func TestExecutionFirewallDeniesScopeMismatch(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	if err := firewall.Catalog.Register(ctx, ToolRef{Name: "write", ServerID: "srv-1", RequiredScopes: []string{"tools.write"}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-1",
		ToolName: "write",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny {
		t.Fatalf("verdict = %s, want DENY", record.Verdict)
	}
	if record.ReasonCode != contracts.ReasonInsufficientPrivilege {
		t.Fatalf("reason = %s, want insufficient privilege", record.ReasonCode)
	}
}

func TestExecutionFirewallDeniesMissingSchemaPin(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	firewall.RequirePinnedSchema = true
	if err := firewall.Catalog.Register(ctx, ToolRef{
		Name:     "local.echo",
		ServerID: "srv-1",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{"type": "string"},
			},
			"required": []string{"text"},
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-1",
		ToolName: "local.echo",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny || record.ReasonCode != contracts.ReasonSchemaViolation {
		t.Fatalf("expected missing pin denial, got %s/%s", record.Verdict, record.ReasonCode)
	}
}

func TestExecutionFirewallDeniesSchemaDrift(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	tool := ToolRef{
		Name:     "write",
		ServerID: "srv-1",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
		},
	}
	if err := firewall.Catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	hash, err := ToolSchemaHash(tool)
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}
	if err := firewall.Catalog.Register(ctx, ToolRef{
		Name:     "write",
		ServerID: "srv-1",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":    map[string]any{"type": "string"},
				"content": map[string]any{"type": "string"},
			},
		},
	}); err != nil {
		t.Fatalf("register drift: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:         "srv-1",
		ToolName:         "write",
		ArgsHash:         "sha256:args",
		PinnedSchemaHash: hash,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny || record.ReasonCode != contracts.ReasonSchemaViolation {
		t.Fatalf("expected schema drift denial, got %s/%s", record.Verdict, record.ReasonCode)
	}
}

func TestExecutionFirewallAllowsApprovedScopedPinnedCall(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	tool := ToolRef{Name: "write", ServerID: "srv-1", RequiredScopes: []string{"tools.write"}}
	if err := firewall.Catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	hash, err := ToolSchemaHash(tool)
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}
	firewall.RequirePinnedSchema = true
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:         "srv-1",
		ToolName:         "write",
		ArgsHash:         "sha256:args",
		GrantedScopes:    []string{"tools.write"},
		PinnedSchemaHash: hash,
		OAuthResource:    "https://helm.local/mcp",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictAllow {
		t.Fatalf("verdict = %s, want ALLOW", record.Verdict)
	}
	if record.RecordHash == "" {
		t.Fatal("allow record was not sealed")
	}
}

func approvedFirewall(t *testing.T) *ExecutionFirewall {
	t.Helper()
	ctx := context.Background()
	registry := NewQuarantineRegistry()
	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-1"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	firewall := NewExecutionFirewall(NewToolCatalog(), registry, "epoch-42")
	firewall.Clock = boundaryFixedClock()
	return firewall
}

func boundaryFixedClock() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	}
}
