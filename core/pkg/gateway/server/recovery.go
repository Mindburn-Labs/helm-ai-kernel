package server

import (
	"context"
	"encoding/json"
	"strconv"

	"connectrpc.com/connect"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func recoveryInput(b *gatewayv1.RecoveryBinding) admission.RecoveryBinding {
	return admission.RecoveryBinding{OperationID: b.GetOperationId(), InstallationID: b.GetInstallationId(), OrgRef: b.GetOrgRef(), OrganizationVersionID: b.GetVersionRef(), Generation: b.GetGeneration(), AuthorityVersionID: b.GetAuthorityVersionRef(), CoveredVersionIDs: append([]string(nil), b.GetCoveredVersionRefs()...), ExpectedPlanDigest: b.GetExpectedPlanDigest()}
}

func recoveryFields(b *gatewayv1.RecoveryBinding) map[string]string {
	fields := map[string]string{"operation_id": b.GetOperationId(), "installation_id": b.GetInstallationId(), "org_ref": b.GetOrgRef(), "organization_version_id": b.GetVersionRef(), "generation": strconv.FormatInt(b.GetGeneration(), 10)}
	if b.GetAuthorityVersionRef() != "" || len(b.GetCoveredVersionRefs()) != 0 || b.GetExpectedPlanDigest() != "" {
		fields["authority_version_id"] = b.GetAuthorityVersionRef()
		fields["version_set_digest"] = admission.RecoveryVersionSetDigest(b.GetCoveredVersionRefs())
		fields["expected_plan_digest"] = b.GetExpectedPlanDigest()
	}
	return fields
}

// A recovery token names one closed binding. In particular, a signed extended
// set cannot authorize a legacy singleton request that omits those fields.
func checkRecoveryBinding(raw json.RawMessage, detailType string, want map[string]string) error {
	if err := checkBinding(raw, detailType, want); err != nil {
		return err
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || len(entries) != 1 || len(entries[0]) != len(want)+1 {
		return permissionDenied("recovery token fields must exactly match the request binding")
	}
	return nil
}

func recoveryProto(f admission.RecoveryFence) *gatewayv1.RecoveryFence {
	return &gatewayv1.RecoveryFence{Binding: &gatewayv1.RecoveryBinding{OperationId: f.OperationID, InstallationId: f.InstallationID, OrgRef: f.OrgRef, VersionRef: f.OrganizationVersionID, Generation: f.Generation, AuthorityVersionRef: f.AuthorityVersionID, CoveredVersionRefs: append([]string(nil), f.CoveredVersionIDs...), ExpectedPlanDigest: f.ExpectedPlanDigest}, PlanDigest: f.PlanDigest, AuthorityRevision: f.AuthorityRevision, InventoryWatermark: f.InventoryWatermark, InventoryCount: f.InventoryCount, UnresolvedCount: f.UnresolvedCount, CheckpointDigest: f.CheckpointDigest, CheckpointWatermark: f.CheckpointWatermark, CutoffWatermark: f.CutoffWatermark}
}

func (s *Server) FenceRecovery(ctx context.Context, req *connect.Request[gatewayv1.FenceRecoveryRequest]) (*connect.Response[gatewayv1.FenceRecoveryResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeStop)
	if err != nil {
		return nil, err
	}
	if err := checkRecoveryBinding(id.AuthorizationDetails, "helm_recovery_fence", recoveryFields(req.Msg.GetBinding())); err != nil {
		return nil, err
	}
	f, existing, err := s.Admission.FenceRecovery(ctx, id.Caller, id.token(), recoveryInput(req.Msg.GetBinding()))
	if err != nil {
		return nil, toRPCError(ctx, "FenceRecovery", err)
	}
	return connect.NewResponse(&gatewayv1.FenceRecoveryResponse{Fence: recoveryProto(f), Existing: existing}), nil
}

func (s *Server) GetRecoveryFence(ctx context.Context, req *connect.Request[gatewayv1.GetRecoveryFenceRequest]) (*connect.Response[gatewayv1.GetRecoveryFenceResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	f, err := s.Admission.GetRecoveryFence(ctx, id.Caller, recoveryInput(req.Msg.GetBinding()))
	if err != nil {
		return nil, toRPCError(ctx, "GetRecoveryFence", err)
	}
	return connect.NewResponse(&gatewayv1.GetRecoveryFenceResponse{Fence: recoveryProto(f)}), nil
}

func (s *Server) BindRecoveryCheckpoint(ctx context.Context, req *connect.Request[gatewayv1.BindRecoveryCheckpointRequest]) (*connect.Response[gatewayv1.BindRecoveryCheckpointResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeStop)
	if err != nil {
		return nil, err
	}
	fields := recoveryFields(req.Msg.GetBinding())
	fields["checkpoint_digest"] = req.Msg.GetCheckpointDigest()
	fields["inventory_watermark"] = req.Msg.GetInventoryWatermark()
	if err := checkRecoveryBinding(id.AuthorizationDetails, "helm_recovery_checkpoint", fields); err != nil {
		return nil, err
	}
	f, err := s.Admission.BindRecoveryCheckpoint(ctx, id.Caller, id.token(), recoveryInput(req.Msg.GetBinding()), req.Msg.GetCheckpointDigest(), req.Msg.GetInventoryWatermark())
	if err != nil {
		return nil, toRPCError(ctx, "BindRecoveryCheckpoint", err)
	}
	return connect.NewResponse(&gatewayv1.BindRecoveryCheckpointResponse{Fence: recoveryProto(f)}), nil
}

func (s *Server) ListRecoveryAttempts(ctx context.Context, req *connect.Request[gatewayv1.ListRecoveryAttemptsRequest]) (*connect.Response[gatewayv1.ListRecoveryAttemptsResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	ids, err := s.Admission.ListRecoveryAttempts(ctx, id.Caller, recoveryInput(req.Msg.GetBinding()), req.Msg.GetAfterAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "ListRecoveryAttempts", err)
	}
	next := ""
	if len(ids) == 100 {
		next = ids[len(ids)-1]
	}
	return connect.NewResponse(&gatewayv1.ListRecoveryAttemptsResponse{AttemptIds: ids, NextAfterAttemptId: next}), nil
}
