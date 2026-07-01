package mcp

// Pre-execution interception overhead benchmarks (MIN-493).
//
// AEGIS (arXiv 2603.12621) reports ~8.3ms median per-call overhead for
// its out-of-process pre-execution firewall. HELM's interception is
// in-process; these benchmarks measure the per-call cost of the full
// AuthorizeToolCall path (quarantine check -> catalog lookup -> scope
// check -> schema hash -> sealed decision record) for the allow and deny
// paths. Run:
//
//	cd core && go test ./pkg/mcp/ -bench BenchmarkPreExecution -run '^$' -benchmem
//
// Narrative: docs/AEGIS_COMPARISON.md.

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func benchFirewall(b *testing.B) (*ExecutionFirewall, context.Context) {
	b.Helper()
	ctx := context.Background()
	catalog := NewToolCatalog()
	registry := NewQuarantineRegistry()
	firewall := NewExecutionFirewall(catalog, registry, "epoch-bench")
	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-bench"}); err != nil {
		b.Fatalf("discover: %v", err)
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{ServerID: "srv-bench", ApproverID: "user:bench", ApprovalReceiptID: "approval-bench", Reason: "benchmark fixture", ToolNames: []string{"crm.read"}}); err != nil {
		b.Fatalf("approve: %v", err)
	}
	if err := catalog.Register(ctx, ToolRef{Name: "crm.read", ServerID: "srv-bench", RequiredScopes: []string{"crm.read"}, Schema: map[string]any{"type": "object"}}); err != nil {
		b.Fatalf("register: %v", err)
	}
	return firewall, ctx
}

func BenchmarkPreExecutionAuthorizeAllow(b *testing.B) {
	firewall, ctx := benchFirewall(b)
	req := ToolCallAuthorization{
		ServerID:      "srv-bench",
		ToolName:      "crm.read",
		ArgsHash:      "sha256:bench-args",
		GrantedScopes: []string{"crm.read"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record, err := firewall.AuthorizeToolCall(ctx, req)
		if err != nil || record.Verdict != contracts.VerdictAllow {
			b.Fatalf("verdict=%s err=%v", record.Verdict, err)
		}
	}
}

func BenchmarkPreExecutionAuthorizeDeny(b *testing.B) {
	firewall, ctx := benchFirewall(b)
	req := ToolCallAuthorization{
		ServerID:      "srv-bench",
		ToolName:      "crm.read",
		ArgsHash:      "sha256:bench-args",
		GrantedScopes: []string{"other.scope"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record, err := firewall.AuthorizeToolCall(ctx, req)
		if err != nil || record.Verdict != contracts.VerdictDeny {
			b.Fatalf("verdict=%s err=%v", record.Verdict, err)
		}
	}
}
