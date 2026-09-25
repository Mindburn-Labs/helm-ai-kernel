package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
		Reason:            "reviewed",
		ToolNames:         []string{"read", "write"},
	})
	visible, err := firewall.FilterVisibleTools(ctx, "srv-1", tools, nil)
	if err != nil {
		t.Fatalf("filter tools: %v", err)
	}
	if len(visible) != 1 || visible[0].Name != "read" {
		t.Fatalf("visible tools = %#v, want only read", visible)
	}
}

func TestExecutionFirewallEscalatesUnknownToolBeforeDispatch(t *testing.T) {
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
	if record.Verdict != contracts.VerdictEscalate {
		t.Fatalf("verdict = %s, want ESCALATE", record.Verdict)
	}
	if record.ReasonCode != contracts.ReasonSchemaViolation {
		t.Fatalf("reason = %s, want schema violation", record.ReasonCode)
	}
	if record.RecordHash == "" {
		t.Fatal("deny record was not sealed")
	}
}

func TestExecutionFirewallEscalatesUnknownServerBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	catalog := NewToolCatalog()
	tool := ToolRef{Name: "local.echo", ServerID: "srv-unknown", Schema: map[string]any{"type": "object"}}
	if err := catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	firewall := NewExecutionFirewall(catalog, NewQuarantineRegistry(), "epoch-42")
	firewall.Clock = boundaryFixedClock()
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-unknown",
		ToolName: "local.echo",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictEscalate {
		t.Fatalf("verdict = %s, want ESCALATE", record.Verdict)
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

// HELM-756: a caller-supplied schema pin bound nothing (the same caller
// supplied the schema), so the firewall no longer reads one. A schema that
// cannot be hashed is still refused.
func TestExecutionFirewallDeniesUnhashableSchema(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	if err := firewall.Catalog.Register(ctx, ToolRef{
		Name:     "write",
		ServerID: "srv-1",
		Schema:   map[string]any{"bad": func() {}},
	}); err != nil {
		t.Skipf("catalog rejects an unhashable schema at registration: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-1",
		ToolName: "write",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny || record.ReasonCode != contracts.ReasonSchemaViolation {
		t.Fatalf("expected schema violation denial, got %s/%s", record.Verdict, record.ReasonCode)
	}
}

func TestExecutionFirewallAllowsApprovedScopedCall(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	tool := ToolRef{Name: "write", ServerID: "srv-1", RequiredScopes: []string{"tools.write"}}
	if err := firewall.Catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:      "srv-1",
		ToolName:      "write",
		ArgsHash:      "sha256:args",
		GrantedScopes: []string{"tools.write"},
		OAuthResource: "https://helm.local/mcp",
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
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
		Reason:            "reviewed",
		ToolNames:         []string{"read", "write", "local.echo", "missing"},
	})
	firewall := NewExecutionFirewall(NewToolCatalog(), registry, "epoch-42")
	firewall.Clock = boundaryFixedClock()
	return firewall
}

func boundaryFixedClock() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	}
}
