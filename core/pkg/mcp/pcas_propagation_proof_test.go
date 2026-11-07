package mcp

// PCAS authorization-propagation proof tests (MIN-494).
//
// arXiv 2605.05440 (PCAS) formalizes authorization propagation across
// multi-agent workflows: transitive delegation, temporal validity, and
// aggregation inference, enforced by a reference monitor over a
// dependency graph. These tests prove which PCAS properties HELM's
// existing engines already enforce — no new engine is introduced — and
// pin the documented gap so the analysis in
// docs/PCAS_AUTHORIZATION_PROPAGATION_GAP_ANALYSIS.md stays truthful.

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func pcasFixedClock(at *time.Time) func() time.Time {
	return func() time.Time { return *at }
}

// PCAS P3 — propagation to the enforcement point: the delegate's narrowed
// authority is what reaches tool dispatch, and the reference monitor
// (ExecutionFirewall) denies out-of-scope calls with a sealed,
// SIEM-consumable decision record. This is HELM's reference-monitor
// equivalent of PCAS's Datalog monitor (CEL/WASM + scope checks).
func TestPCASPropagatedScopeEnforcedAtDispatchWithEvidence(t *testing.T) {
	ctx := context.Background()
	catalog := NewToolCatalog()
	registry := NewQuarantineRegistry()
	firewall := NewExecutionFirewall(catalog, registry, "epoch-pcas")
	firewall.Clock = boundaryFixedClock()
	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-pcas"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{ServerID: "srv-pcas", ApproverID: "user:root", ApprovalReceiptID: "approval-pcas", Reason: "pcas fixture", ToolNames: []string{"crm.read", "crm.export"}})
	for _, tool := range []ToolRef{
		{Name: "crm.read", ServerID: "srv-pcas", RequiredScopes: []string{"crm.read"}, Schema: map[string]any{"type": "object"}},
		{Name: "crm.export", ServerID: "srv-pcas", RequiredScopes: []string{"crm.export"}, Schema: map[string]any{"type": "object"}},
	} {
		if err := catalog.Register(ctx, tool); err != nil {
			t.Fatalf("register %s: %v", tool.Name, err)
		}
	}

	// The worker's propagated authority from P1 is crm.read only.
	propagated := []string{"crm.read"}

	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:      "srv-pcas",
		ToolName:      "crm.read",
		ArgsHash:      "sha256:pcas-args",
		GrantedScopes: propagated,
	})
	if err != nil || record.Verdict != contracts.VerdictAllow {
		t.Fatalf("in-scope propagated call should be allowed: verdict=%s err=%v", record.Verdict, err)
	}

	record, err = firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:      "srv-pcas",
		ToolName:      "crm.export",
		ArgsHash:      "sha256:pcas-args",
		GrantedScopes: propagated,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictDeny || record.ReasonCode != contracts.ReasonInsufficientPrivilege {
		t.Fatalf("out-of-scope propagated call must deny INSUFFICIENT_PRIVILEGE, got %s/%s", record.Verdict, record.ReasonCode)
	}
	if record.RecordHash == "" {
		t.Fatal("denial must produce a sealed decision record")
	}
}

// PCAS GAP — aggregation inference: PCAS denies a request when the
// *combination* of individually-permitted results crosses a policy
// boundary. HELM evaluates each tool call independently today; this test
// pins the documented gap. If it starts failing because an aggregation
// policy layer landed, update
// docs/PCAS_AUTHORIZATION_PROPAGATION_GAP_ANALYSIS.md accordingly.
func TestPCASAggregationInferenceGapIsDocumentedBehavior(t *testing.T) {
	ctx := context.Background()
	catalog := NewToolCatalog()
	registry := NewQuarantineRegistry()
	firewall := NewExecutionFirewall(catalog, registry, "epoch-pcas")
	firewall.Clock = boundaryFixedClock()
	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-pcas"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{ServerID: "srv-pcas", ApproverID: "user:root", ApprovalReceiptID: "approval-pcas", Reason: "pcas fixture", ToolNames: []string{"directory.lookup"}})
	if err := catalog.Register(ctx, ToolRef{Name: "directory.lookup", ServerID: "srv-pcas", RequiredScopes: []string{"dir.read"}, Schema: map[string]any{"type": "object"}}); err != nil {
		t.Fatalf("register: %v", err)
	}

	for i := 0; i < 2; i++ {
		record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
			ServerID:      "srv-pcas",
			ToolName:      "directory.lookup",
			ArgsHash:      "sha256:pcas-lookup",
			GrantedScopes: []string{"dir.read"},
		})
		if err != nil || record.Verdict != contracts.VerdictAllow {
			t.Fatalf("call %d: individually-permitted call should allow: verdict=%s err=%v", i, record.Verdict, err)
		}
	}
	t.Log("aggregation inference across calls is not evaluated — documented PCAS gap (see gap analysis doc)")
}
