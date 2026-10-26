package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
	"github.com/google/uuid"
)

func TestPostgresRecoveryWireRequiresExactCurrentOperatorAuthority(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()
	_, err := w.ensure("tenant-a", serviceSpec(adminProvision), serviceSpec(testActor), humanSpec(adminOwner, adminOwner))
	must(t, err)
	proposed, err := w.effects.Propose(ctx, withToken(&gatewayv1.ProposeRequest{IdempotencyKey: "recovery-provision", Effect: &gatewayv1.EffectDescriptor{
		EffectType: effectargs.AuthorityProvision, Target: adminOrg, Arguments: e2ePlan(t, effectargs.AuthorityProvision, "", "recovery-v1", 100, 80, time.Now())}}, w.token("tenant-a", adminProvision, ScopePropose)))
	must(t, err)
	a := proposed.Msg.GetAttempt()
	digest := a.GetPendingApproval().GetApprovalDigest()
	proof := w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeStepUp, binding(a.GetAttemptId(), digest, "webauthn"))
	_, err = w.effects.Approve(ctx, withToken(&gatewayv1.ApproveRequest{AttemptId: a.GetAttemptId(), ApprovalDigest: digest, StepUpProof: proof}, w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeDecide, decision(a.GetAttemptId(), "approve"))))
	must(t, err)
	_, err = w.effects.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: a.GetAttemptId()}, w.iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })))
	must(t, err)
	b := &gatewayv1.RecoveryBinding{OperationId: uuid.NewString(), InstallationId: "fixture-installation", OrgRef: adminOrg, VersionRef: "recovery-v1"}
	request := &gatewayv1.FenceRecoveryRequest{Binding: b}
	stop := func(edit ...func(*tokenClaims)) string {
		return w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeStop, edit...)
	}
	for name, token := range map[string]string{
		"unbound":            stop(),
		"ordinary stop":      stop(bound("helm_stop", map[string]string{"idempotency_key": "x", "scope_kind": "tenant", "scope_key": ""})),
		"read":               w.token("tenant-a", adminOwner, ScopeRead),
		"wrong organization": stop(bound("helm_recovery_fence", map[string]string{"operation_id": b.OperationId, "installation_id": b.InstallationId, "org_ref": "org:other", "organization_version_id": b.VersionRef, "generation": "0"})),
	} {
		_, err := w.effects.FenceRecovery(ctx, withToken(request, token))
		wantRPCError(t, name, err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	token := stop(bound("helm_recovery_fence", recoveryFields(b)))
	response, err := w.effects.FenceRecovery(ctx, withToken(request, token))
	must(t, err)
	f := response.Msg.GetFence()
	if f.GetBinding().GetGeneration() != 1 || f.GetCutoffWatermark() == "" {
		t.Fatalf("native fence=%+v", f)
	}
	replayed, err := w.effects.FenceRecovery(ctx, withToken(request, token))
	must(t, err)
	if !replayed.Msg.GetExisting() {
		t.Fatal("exact replay created another fence")
	}
	read := w.token("tenant-a", adminOwner, ScopeRead)
	current := f.GetBinding()
	_, err = w.effects.GetRecoveryFence(ctx, withToken(&gatewayv1.GetRecoveryFenceRequest{Binding: current}, read))
	must(t, err)
	_, err = w.effects.GetRecoveryFence(ctx, withToken(&gatewayv1.GetRecoveryFenceRequest{Binding: current}, w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeRead, func(c *tokenClaims) { c.WorkspaceID = "other-workspace" })))
	wantRPCError(t, "cross workspace read", err, connect.CodeNotFound, "")
	cp := &gatewayv1.BindRecoveryCheckpointRequest{Binding: current, CheckpointDigest: strings.Repeat("a", 64), InventoryWatermark: f.GetInventoryWatermark()}
	_, err = w.effects.BindRecoveryCheckpoint(ctx, withToken(cp, stop(bound("helm_recovery_fence", recoveryFields(current)))))
	wantRPCError(t, "fence token on checkpoint", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	fields := recoveryFields(current)
	fields["checkpoint_digest"] = cp.CheckpointDigest
	fields["inventory_watermark"] = cp.InventoryWatermark
	_, err = w.effects.BindRecoveryCheckpoint(ctx, withToken(cp, stop(bound("helm_recovery_checkpoint", fields))))
	must(t, err)
	// There is no resume operation in this capability. A new exact operation
	// advances the generation and makes the old checkpoint reference unusable.
	newer := &gatewayv1.RecoveryBinding{OperationId: uuid.NewString(), InstallationId: b.InstallationId, OrgRef: b.OrgRef, VersionRef: b.VersionRef, Generation: 1}
	_, err = w.effects.FenceRecovery(ctx, withToken(&gatewayv1.FenceRecoveryRequest{Binding: newer}, stop(bound("helm_recovery_fence", recoveryFields(newer)))))
	must(t, err)
	_, err = w.effects.GetRecoveryFence(ctx, withToken(&gatewayv1.GetRecoveryFenceRequest{Binding: current}, read))
	wantRPCError(t, "stale generation read", err, connect.CodeNotFound, "")
}
