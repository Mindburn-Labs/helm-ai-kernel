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

// PCAS P1 — transitive delegation: authority propagates only through an
// explicit chain, and every hop is bounded by the delegator's effective
// scope (no privilege amplification).
func TestPCASTransitiveDelegationBoundedPropagation(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	verifier := NewAIPVerifier(WithAIPClock(pcasFixedClock(&now)), WithAIPSignatureVerifier(aipTestSignatureVerifier))
	expiry := now.Add(time.Hour)

	if err := verifier.RegisterDelegation(DelegationClaim{
		DelegatorID: "user:root",
		DelegateID:  "agent:orchestrator",
		Scope:       []string{"crm.read", "crm.export", "mail.send"},
		ExpiresAt:   expiry,
		Signature:   "sig-fixture",
	}); err != nil {
		t.Fatalf("register hop 1: %v", err)
	}
	if err := verifier.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent:orchestrator",
		DelegateID:  "agent:planner",
		Scope:       []string{"crm.read", "crm.export"},
		ExpiresAt:   expiry,
		Signature:   "sig-fixture",
	}); err != nil {
		t.Fatalf("register hop 2: %v", err)
	}
	if err := verifier.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent:planner",
		DelegateID:  "agent:worker",
		Scope:       []string{"crm.read"},
		ExpiresAt:   expiry,
		Signature:   "sig-fixture",
	}); err != nil {
		t.Fatalf("register hop 3: %v", err)
	}

	// Worker holds exactly the propagated, narrowed authority.
	if ok, err := verifier.VerifyAuthority("agent:worker", "crm.read"); err != nil || !ok {
		t.Fatalf("worker should hold propagated crm.read: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifier.VerifyAuthority("agent:worker", "crm.export"); ok {
		t.Fatal("worker must not hold authority that was narrowed away at hop 3")
	}
	if ok, _ := verifier.VerifyAuthority("agent:worker", "mail.send"); ok {
		t.Fatal("worker must not hold authority dropped at hop 2")
	}

	// Privilege amplification at any hop is rejected at registration —
	// with a valid signature, so the rejection is on scope, not signing.
	if err := verifier.RegisterDelegation(DelegationClaim{
		DelegatorID: "agent:planner",
		DelegateID:  "agent:rogue",
		Scope:       []string{"mail.send"},
		ExpiresAt:   expiry,
		Signature:   "sig-fixture",
	}); err == nil {
		t.Fatal("delegating authority the delegator does not hold must fail closed")
	}
}

// PCAS P2 — temporal validity: propagated authority is valid only within
// the claim's validity window; expiry revokes downstream authority with
// no action required (fail-closed).
func TestPCASTemporalValidityExpiryRevokesAuthority(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	verifier := NewAIPVerifier(WithAIPClock(pcasFixedClock(&now)), WithAIPSignatureVerifier(aipTestSignatureVerifier))

	if err := verifier.RegisterDelegation(DelegationClaim{
		DelegatorID: "user:root",
		DelegateID:  "agent:worker",
		Scope:       []string{"crm.read"},
		ExpiresAt:   now.Add(10 * time.Minute),
		Signature:   "sig-fixture",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if ok, err := verifier.VerifyAuthority("agent:worker", "crm.read"); err != nil || !ok {
		t.Fatalf("authority should be valid inside the window: ok=%v err=%v", ok, err)
	}

	now = now.Add(11 * time.Minute)
	if ok, _ := verifier.VerifyAuthority("agent:worker", "crm.read"); ok {
		t.Fatal("expired delegation must revoke authority fail-closed")
	}
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
	if _, err := registry.Approve(ctx, ApprovalDecision{ServerID: "srv-pcas", ApproverID: "user:root", ApprovalReceiptID: "approval-pcas"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
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
	if _, err := registry.Approve(ctx, ApprovalDecision{ServerID: "srv-pcas", ApproverID: "user:root", ApprovalReceiptID: "approval-pcas"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
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
