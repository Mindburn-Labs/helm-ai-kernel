package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func recoveryWireFixture(t *testing.T) (*adminWire, *gatewayv1.RecoveryBinding) {
	t.Helper()
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
	return w, b
}

func TestPostgresRecoveryWireRequiresExactCurrentOperatorAuthority(t *testing.T) {
	w, b := recoveryWireFixture(t)
	ctx := context.Background()
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

func TestPostgresRecoveryWireBindsExactCPLifecycleLineage(t *testing.T) {
	w, b := recoveryWireFixture(t)
	ctx := context.Background()
	read := w.token("tenant-a", adminOwner, ScopeRead)
	applied, err := w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: adminOrg}, read))
	must(t, err)
	b.VersionRef, b.AuthorityVersionRef = "recovery-v2", "recovery-v1"
	// Exercise the full bounded wire contract, including IDs at their maximum
	// length. Only recovery RPCs admit this message size.
	for i := 0; i < 4094; i++ {
		b.CoveredVersionRefs = append(b.CoveredVersionRefs, fmt.Sprintf("alias-%04d-", i)+strings.Repeat("x", 117))
	}
	b.CoveredVersionRefs = append(b.CoveredVersionRefs, "recovery-v1", "recovery-v2")
	b.ExpectedPlanDigest = applied.Msg.GetProvisioning().GetPlanDigest()
	stop := func(binding *gatewayv1.RecoveryBinding) string {
		return w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeStop, bound("helm_recovery_fence", recoveryFields(binding)))
	}
	token := stop(b)
	for name, edit := range map[string]func(*gatewayv1.RecoveryBinding){
		"changed set":               func(b *gatewayv1.RecoveryBinding) { b.CoveredVersionRefs = []string{"recovery-v1", "recovery-v2"} },
		"changed authority version": func(b *gatewayv1.RecoveryBinding) { b.AuthorityVersionRef = b.CoveredVersionRefs[0] },
		"changed expected plan":     func(b *gatewayv1.RecoveryBinding) { b.ExpectedPlanDigest = strings.Repeat("b", 64) },
	} {
		changed := proto.Clone(b).(*gatewayv1.RecoveryBinding)
		edit(changed)
		_, err := w.effects.FenceRecovery(ctx, withToken(&gatewayv1.FenceRecoveryRequest{Binding: changed}, token))
		wantRPCError(t, name, err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	response, err := w.effects.FenceRecovery(ctx, withToken(&gatewayv1.FenceRecoveryRequest{Binding: b}, token))
	must(t, err)
	fence := response.Msg.GetFence()
	want := proto.Clone(b).(*gatewayv1.RecoveryBinding)
	want.Generation++
	if !proto.Equal(fence.GetBinding(), want) {
		t.Fatalf("native typed binding differs: %v", fence.GetBinding())
	}
	_, err = w.effects.GetRecoveryFence(ctx, withToken(&gatewayv1.GetRecoveryFenceRequest{Binding: want}, read))
	must(t, err)
	changed := proto.Clone(want).(*gatewayv1.RecoveryBinding)
	changed.CoveredVersionRefs = []string{"recovery-v1", "recovery-v2"}
	_, err = w.effects.GetRecoveryFence(ctx, withToken(&gatewayv1.GetRecoveryFenceRequest{Binding: changed}, read))
	wantRPCError(t, "changed exact read set", err, connect.CodeNotFound, "")
	checkpoint := &gatewayv1.BindRecoveryCheckpointRequest{Binding: want, CheckpointDigest: strings.Repeat("a", 64), InventoryWatermark: fence.GetInventoryWatermark()}
	fields := recoveryFields(want)
	fields["checkpoint_digest"], fields["inventory_watermark"] = checkpoint.CheckpointDigest, checkpoint.InventoryWatermark
	checkpointToken := w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeStop, bound("helm_recovery_checkpoint", fields))
	_, err = w.effects.BindRecoveryCheckpoint(ctx, withToken(checkpoint, checkpointToken))
	must(t, err)
}
