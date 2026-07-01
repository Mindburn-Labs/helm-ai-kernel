package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestObserveGrantLabelsRecordAndPermitsShadowDispatch(t *testing.T) {
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
	if record.Verdict != contracts.VerdictEscalate {
		t.Fatalf("verdict = %s, want ESCALATE (shadow mode must not change verdicts)", record.Verdict)
	}
	if record.EnforcementMode != contracts.EnforcementModeShadow {
		t.Fatalf("enforcement mode = %q, want shadow", record.EnforcementMode)
	}
	if record.ObserveGrantID != "og-1" {
		t.Fatalf("observe grant id = %q, want og-1", record.ObserveGrantID)
	}
	if record.RecordHash == "" {
		t.Fatal("shadow records must still be sealed")
	}
	if !ShouldDispatch(record) {
		t.Fatal("labeled shadow ESCALATE record should permit dispatch")
	}
}

func TestExpiredObserveGrantRestoresEnforcement(t *testing.T) {
	ctx := context.Background()
	firewall := approvedFirewall(t)
	firewall.Observe = &ObserveGrant{
		GrantID:   "og-1",
		Reason:    "onboarding",
		ExpiresAt: boundaryFixedClock()().Add(-time.Minute),
	}

	record, err := firewall.AuthorizeToolCall(ctx, ToolCallAuthorization{
		ServerID: "srv-1",
		ToolName: "missing",
		ArgsHash: "sha256:args",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if record.EnforcementMode != "" {
		t.Fatalf("enforcement mode = %q, want empty after expiry", record.EnforcementMode)
	}
	if ShouldDispatch(record) {
		t.Fatal("expired grant must not permit ESCALATE dispatch")
	}
}

func TestObserveGrantActiveRules(t *testing.T) {
	now := boundaryFixedClock()()
	var nilGrant *ObserveGrant
	if nilGrant.Active(now) {
		t.Fatal("nil grant must be inactive")
	}
	if (&ObserveGrant{GrantID: "", ExpiresAt: now.Add(time.Hour)}).Active(now) {
		t.Fatal("grant without id must be inactive")
	}
	if (&ObserveGrant{GrantID: "og-1"}).Active(now) {
		t.Fatal("open-ended grant (zero expiry) must be inactive")
	}
	if !(&ObserveGrant{GrantID: "og-1", ExpiresAt: now.Add(time.Hour)}).Active(now) {
		t.Fatal("bounded grant with id must be active")
	}
}

func TestShouldDispatchFailClosed(t *testing.T) {
	if ShouldDispatch(contracts.ExecutionBoundaryRecord{Verdict: contracts.VerdictAllow}) {
		t.Fatal("unsealed record must not dispatch")
	}
	deny := contracts.ExecutionBoundaryRecord{
		Verdict:    contracts.VerdictDeny,
		RecordHash: "sha256:x",
	}
	if ShouldDispatch(deny) {
		t.Fatal("unlabeled DENY must not dispatch")
	}
	deny.EnforcementMode = contracts.EnforcementModeShadow
	if ShouldDispatch(deny) {
		t.Fatal("shadow label without grant id must not dispatch")
	}
	deny.ObserveGrantID = "og-1"
	if !ShouldDispatch(deny) {
		t.Fatal("sealed, labeled shadow DENY should dispatch")
	}
}

func TestShadowModeValidationInvariants(t *testing.T) {
	base := contracts.ExecutionBoundaryRecord{
		RecordID:    "rec-1",
		Verdict:     contracts.VerdictAllow,
		PolicyEpoch: "epoch-42",
		CreatedAt:   boundaryFixedClock()(),
	}

	shadowNoGrant := base
	shadowNoGrant.EnforcementMode = contracts.EnforcementModeShadow
	if _, err := shadowNoGrant.Seal(); err == nil {
		t.Fatal("shadow mode without grant id must fail validation")
	}

	grantNoMode := base
	grantNoMode.ObserveGrantID = "og-1"
	if _, err := grantNoMode.Seal(); err == nil {
		t.Fatal("grant id without shadow mode must fail validation")
	}

	badMode := base
	badMode.EnforcementMode = "permissive"
	if _, err := badMode.Seal(); err == nil {
		t.Fatal("unknown enforcement mode must fail validation")
	}

	valid := base
	valid.EnforcementMode = contracts.EnforcementModeShadow
	valid.ObserveGrantID = "og-1"
	if _, err := valid.Seal(); err != nil {
		t.Fatalf("valid shadow record should seal: %v", err)
	}
}
