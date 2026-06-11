package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// TestObserveModeEmitsCounterfactualReceipt is the deliverable-2 wiring proof:
// an action evaluated under an active observe grant yields a sealed
// counterfactual receipt carrying the would-have verdict, reason code, and the
// grant id — with no enforcement.
func TestObserveModeEmitsCounterfactualReceipt(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	firewall.Observe = &ObserveGrant{
		GrantID:   "og-1",
		Reason:    "onboarding",
		ExpiresAt: boundaryFixedClock()().Add(time.Hour),
	}

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

	cf, err := firewall.CounterfactualReceiptFor(record)
	if err != nil {
		t.Fatalf("counterfactual receipt: %v", err)
	}
	if cf.Enforcement != contracts.EnforcementCounterfactual {
		t.Fatalf("enforcement = %q, want counterfactual", cf.Enforcement)
	}
	if cf.WouldHaveVerdict != contracts.VerdictDeny {
		t.Fatalf("would-have verdict = %q, want DENY", cf.WouldHaveVerdict)
	}
	if cf.ReasonCode != record.ReasonCode {
		t.Fatalf("reason code = %q, want %q", cf.ReasonCode, record.ReasonCode)
	}
	if cf.ObserveGrantID != "og-1" {
		t.Fatalf("observe grant id = %q, want og-1", cf.ObserveGrantID)
	}
	if cf.BoundaryRecordHash != record.RecordHash || cf.BoundaryRecordID != record.RecordID {
		t.Fatal("counterfactual receipt must bind the sealed boundary record")
	}
	if cf.ReceiptHash == "" {
		t.Fatal("counterfactual receipt must be sealed")
	}
}

// TestNoCounterfactualWithoutGrant proves the fail-closed rule: a record that is
// not shadow-labeled (no active grant) has no counterfactual standing.
func TestNoCounterfactualWithoutGrant(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	// No observe grant set: enforce mode.

	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-1",
		ToolName: "missing",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := firewall.CounterfactualReceiptFor(record); err == nil {
		t.Fatal("an enforce-mode record must not yield a counterfactual receipt (no grant, no observe mode)")
	}
}

// TestCounterfactualForAllowUnderObserve confirms ALLOW actions also get
// counterfactual receipts so the summary can report coverage, not only blocks.
func TestCounterfactualForAllowUnderObserve(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	tool := ToolRef{Name: "write", ServerID: "srv-1", RequiredScopes: []string{"tools.write"}}
	if err := firewall.Catalog.Register(ctx, tool); err != nil {
		t.Fatalf("register: %v", err)
	}
	firewall.Observe = &ObserveGrant{
		GrantID:   "og-allow",
		Reason:    "onboarding",
		ExpiresAt: boundaryFixedClock()().Add(time.Hour),
	}

	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID:      "srv-1",
		ToolName:      "write",
		ArgsHash:      "sha256:args",
		GrantedScopes: []string{"tools.write"},
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.Verdict != contracts.VerdictAllow {
		t.Fatalf("verdict = %s, want ALLOW", record.Verdict)
	}
	cf, err := firewall.CounterfactualReceiptFor(record)
	if err != nil {
		t.Fatalf("counterfactual receipt for allow: %v", err)
	}
	if cf.WouldHaveVerdict != contracts.VerdictAllow {
		t.Fatalf("would-have verdict = %q, want ALLOW", cf.WouldHaveVerdict)
	}
}
