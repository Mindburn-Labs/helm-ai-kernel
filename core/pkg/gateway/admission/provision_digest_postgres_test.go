package admission

import (
	"bytes"
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// An authority change is approved for its exact plan. A newer applied base
// cannot turn that approval into permission for an older or edited plan.
func TestPostgresProvisionAmountChangeNeedsNewStepUpAndMovedBaseFails(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	f.applyBase(tenantA, f.plan(effectargs.AuthorityProvision, "", "v1", nil))
	base := f.provisioning(tenantA).Digest

	propose := func(key, version, digest string, org, team int64) Attempt {
		t.Helper()
		raw := f.plan(effectargs.AuthorityProvision, digest, version, limits(org, team))
		a, existing, err := f.svc.Propose(ctx, organization, planProposal(key, effectargs.AuthorityProvision, raw))
		must(t, err)
		wantState(t, key, a, "ESCALATED", contracts.ReasonApprovalRequired)
		if existing || a.Permit != nil || len(a.Exposures) != 0 {
			t.Fatalf("%s was reused, permitted, or reserved before approval: %+v existing=%v", key, a, existing)
		}
		return a
	}
	approve := func(a Attempt) {
		t.Helper()
		got, existing, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"),
			withProof(approval(a, "approve exact plan"), stepUpProof()))
		must(t, err)
		wantState(t, "approved plan", got, "ADMITTED", "")
		if existing || got.Permit == nil || !bytes.Equal(got.Permit.ArgumentDigest, a.ArgumentDigest) {
			t.Fatalf("approval did not bind the exact plan: %+v existing=%v", got, existing)
		}
	}

	a1 := propose("plan-a1", "v2", base, 200, 150)
	approve(a1)
	// A different approved plan wins the base before a1 can Dispatch.
	ahead := propose("plan-ahead", "v3", base, 190, 140)
	approve(ahead)
	advanced, _, err := f.svc.Dispatch(ctx, workload, ahead.ID)
	must(t, err)
	wantOutcome(t, "newer applied base", advanced, "OBSERVED", "SUCCEEDED", "")
	advancedDigest := f.provisioning(tenantA).Digest

	stale, _, err := f.svc.Dispatch(ctx, workload, a1.ID)
	must(t, err)
	wantOutcome(t, "approved plan on moved base", stale, "OBSERVED", "FAILED", contracts.ReasonPreconditionFailed)
	if len(stale.Exposures) != 0 || f.provisioning(tenantA).Digest != advancedDigest {
		t.Fatal("a stale approved plan reserved spend or changed the applied plan")
	}

	// Changing only the amount creates a separate digest and fresh approval.
	a2 := propose("plan-a2", "v4", advancedDigest, 210, 160)
	if a2.ID == a1.ID || bytes.Equal(a2.ArgumentDigest, a1.ArgumentDigest) || bytes.Equal(a2.ApprovalDigest, a1.ApprovalDigest) {
		t.Fatal("changed amount reused the first attempt or either approval binding")
	}
	wrong := approval(a2, "stale approval")
	wrong.ApprovalDigest = a1.ApprovalDigest
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(wrong, stepUpProof()))
	wantRefusal(t, "stale approval digest", err, CodeFailedPrecondition, "")
	unchanged, err := f.svc.Get(ctx, organization, a2.ID)
	must(t, err)
	if unchanged.State != "ESCALATED" || unchanged.Permit != nil || unchanged.Approval != nil {
		t.Fatalf("stale approval changed the second plan: %+v", unchanged)
	}
	approve(a2)
	applied, _, err := f.svc.Dispatch(ctx, workload, a2.ID)
	must(t, err)
	wantOutcome(t, "separately approved changed amount", applied, "OBSERVED", "SUCCEEDED", "")
	if f.limitValue(tenantA, f.provisioning(tenantA), planOrg) != 210 {
		t.Fatal("the separately approved limit was not applied")
	}
}
